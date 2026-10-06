import { randomUUID } from "node:crypto";
import { and, desc, eq, isNull } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { DEFAULT_TENANT_SETTINGS, partnerConsents, partnerEscalations, tenants } from "@/db/schema";
import { withScope } from "@/db/scope";
import { can, dbScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { LIST_PRICE_CENTS, NONPROFIT_DISCOUNT_BPS } from "@/lib/billing/catalogue";
import { cobrandLine } from "@/lib/tenancy/brand";
import { actor, AccessDenied } from "./common";
import { quoteFor, usageDashboard, type Plan, type UsageTotals } from "./billing";

/** Share of the ex-GST amount that is the partner's reporting input. This does not pay anyone. */
export const PARTNER_REVENUE_SHARE_BPS = 2000;

export const PARTNER_CONSENT_STATEMENT =
  "The customer agrees this IT provider can open the tenancy to provide IT support. blakSOC and Yuma IT stay named on the portal and on reports.";

export function partnerHome(ctx: AccessContext): string | null {
  for (const grant of ctx.grants) {
    if (grant.roleKey !== "partner_admin" || !grant.tenantId || !grant.permissions.has("tenant:manage")) continue;
    const tenant = ctx.tenants.find((item) => item.id === grant.tenantId);
    if (tenant && tenant.kind !== "partner") continue;
    return grant.tenantId;
  }
  return null;
}

export function partnerAnalystHome(ctx: AccessContext): string | null {
  for (const grant of ctx.grants) {
    if ((grant.roleKey !== "partner_admin" && grant.roleKey !== "partner_analyst") || !grant.tenantId) continue;
    const tenant = ctx.tenants.find((item) => item.id === grant.tenantId);
    if (tenant && tenant.kind !== "partner") continue;
    return grant.tenantId;
  }
  return null;
}

/** Ex-GST cents the share rate applies to. A real quote wins. Otherwise the #9 list price. */
export function shareBaseCents(plan: Pick<Plan, "tier" | "nonprofit" | "discountBps">, quoteExGst: number | null): number {
  if (quoteExGst != null) return quoteExGst;
  const list = LIST_PRICE_CENTS[plan.tier];
  const discount = plan.discountBps > 0 ? plan.discountBps : plan.nonprofit ? NONPROFIT_DISCOUNT_BPS : 0;
  const bps = Math.min(10_000, Math.max(0, discount));
  return Math.round((list * (10_000 - bps)) / 10_000);
}

export function revenueShareCents(exGstCents: number, shareBps = PARTNER_REVENUE_SHARE_BPS): number {
  return Math.round((exGstCents * shareBps) / 10_000);
}

export async function cobrandLabel(tenantId: string): Promise<string | null> {
  const [row] = await systemDb()
    .select({ parentId: tenants.parentId, name: tenants.name, brandName: tenants.brandName, kind: tenants.kind })
    .from(tenants)
    .where(eq(tenants.id, tenantId));
  if (!row) return null;
  if (row.kind === "partner") return cobrandLine(row.name, row.brandName);
  if (!row.parentId) return null;
  const [parent] = await systemDb()
    .select({ name: tenants.name, brandName: tenants.brandName, kind: tenants.kind })
    .from(tenants)
    .where(eq(tenants.id, row.parentId));
  if (!parent || parent.kind !== "partner") return null;
  return cobrandLine(parent.name, parent.brandName);
}

/**
 * Creates the customer under the partner and records consent in the same transaction.
 * Access without an active consent row is rejected by RLS.
 */
export async function grantPartnerCustomer(
  ctx: AccessContext,
  partnerId: string,
  input: { name: string; slug: string; sectors: string[]; deploymentMode: "shared" | "dedicated" },
) {
  if (partnerHome(ctx) !== partnerId && !(ctx.isPlatform && can(ctx, "tenant:manage"))) throw new AccessDenied("partner admin required");
  if (!/^[a-z0-9-]{2,40}$/.test(input.slug)) throw new Error("slug must be lowercase letters, digits, hyphens");
  return withScope({ tenantIds: [partnerId], grantIds: [partnerId], platform: ctx.isPlatform }, async (tx) => {
    const [partner] = await tx.select({ id: tenants.id, kind: tenants.kind }).from(tenants).where(eq(tenants.id, partnerId));
    if (!partner || partner.kind !== "partner") throw new AccessDenied("partner");
    // The new customer is not selectable until the consent row exists, so RETURNING would fail RLS.
    const id = randomUUID();
    await tx.insert(tenants).values({
      id,
      name: input.name,
      slug: input.slug,
      sectors: input.sectors,
      deploymentMode: input.deploymentMode,
      kind: "customer",
      parentId: partnerId,
      settings: DEFAULT_TENANT_SETTINGS,
    });
    await tx.insert(partnerConsents).values({
      customerTenantId: id,
      partnerTenantId: partnerId,
      consentedBy: ctx.principal.userId,
      statement: PARTNER_CONSENT_STATEMENT,
    });
    const [created] = await tx.select().from(tenants).where(eq(tenants.id, id));
    if (!created) throw new AccessDenied("partner");
    await audit(tx, {
      ...actor(ctx),
      tenantId: created!.id,
      action: "partner.consent",
      targetType: "tenant",
      targetId: created!.id,
      detail: { partnerId, statement: PARTNER_CONSENT_STATEMENT },
    });
    await audit(tx, {
      ...actor(ctx),
      tenantId: null,
      action: "tenant.create",
      targetType: "tenant",
      targetId: created!.id,
      detail: { ...input, parentId: partnerId, kind: "customer" },
    });
    return created!;
  });
}

export async function revokePartnerAccess(ctx: AccessContext, customerId: string) {
  const partnerId = partnerHome(ctx);
  if (!partnerId && !(ctx.isPlatform && can(ctx, "tenant:manage"))) throw new AccessDenied("partner admin required");
  const grants = partnerId ? [partnerId] : [customerId];
  return withScope({ tenantIds: [customerId, ...grants], grantIds: grants, platform: ctx.isPlatform }, async (tx) => {
    const [existing] = await tx
      .select({ id: partnerConsents.id })
      .from(partnerConsents)
      .where(and(eq(partnerConsents.customerTenantId, customerId), partnerId ? eq(partnerConsents.partnerTenantId, partnerId) : undefined, isNull(partnerConsents.revokedAt)));
    if (!existing) throw new AccessDenied("consent");
    // Audit while the consent is still active. RLS stops seeing the customer once revokedAt is set.
    await audit(tx, { ...actor(ctx), tenantId: customerId, action: "partner.revoke", targetType: "partner_consent", targetId: existing.id, detail: { partnerId, customerId } });
    const [row] = await tx.update(partnerConsents).set({ revokedAt: new Date() }).where(eq(partnerConsents.id, existing.id)).returning({ id: partnerConsents.id });
    if (!row) throw new AccessDenied("consent");
    return row;
  });
}

export async function setPartnerBrand(ctx: AccessContext, partnerId: string, brandName: string) {
  if (partnerHome(ctx) !== partnerId && !(ctx.isPlatform && can(ctx, "tenant:manage"))) throw new AccessDenied("partner admin required");
  const name = brandName.trim().slice(0, 80);
  if (!name) throw new Error("brand name required");
  return withScope(dbScope(ctx, [partnerId]), async (tx) => {
    const [row] = await tx
      .update(tenants)
      .set({ brandName: name })
      .where(and(eq(tenants.id, partnerId), eq(tenants.kind, "partner")))
      .returning({ id: tenants.id, brandName: tenants.brandName, name: tenants.name });
    if (!row) throw new AccessDenied("partner");
    await audit(tx, { ...actor(ctx), tenantId: partnerId, action: "partner.brand", targetType: "tenant", targetId: partnerId, detail: { brandName: name } });
    return { ...row, cobrand: cobrandLine(row.name, row.brandName) };
  });
}

export type PartnerCommercialRow = {
  id: string;
  name: string;
  slug: string;
  plan: Plan;
  usage: UsageTotals;
  shareBps: number;
  priceSource: "quote" | "list";
  exGstCents: number;
  shareExGstCents: number;
};

/** Customers, this month's usage, and the revenue-share inputs from the #9 price. */
export async function partnerCommercialReport(ctx: AccessContext, partnerId: string): Promise<PartnerCommercialRow[]> {
  if (partnerHome(ctx) !== partnerId && !(ctx.isPlatform && can(ctx, "mssp:read"))) throw new AccessDenied("partner report");
  const childIds = new Set(ctx.tenants.filter((t) => t.kind === "customer" && t.parentId === partnerId).map((t) => t.id));
  const usage = await usageDashboard(ctx);
  const rows: PartnerCommercialRow[] = [];
  for (const row of usage) {
    if (!childIds.has(row.id)) continue;
    const quote = await quoteFor(ctx, row.id);
    const quoted = quote && !("error" in quote) ? quote.exGstCents : null;
    const exGstCents = shareBaseCents(row.plan, quoted);
    rows.push({
      id: row.id,
      name: row.name,
      slug: row.slug,
      plan: row.plan,
      usage: row.usage,
      shareBps: PARTNER_REVENUE_SHARE_BPS,
      priceSource: quoted == null ? "list" : "quote",
      exGstCents,
      shareExGstCents: revenueShareCents(exGstCents),
    });
  }
  return rows;
}

/** Records an escalation for the Yuma IT SOC. No outbound ticket is opened. */
export async function escalateToSoc(ctx: AccessContext, input: { tenantId: string; note: string; incidentId?: string | null }) {
  const partnerId = partnerAnalystHome(ctx);
  if (!partnerId) throw new AccessDenied("partner role required");
  if (!can(ctx, "incident:write", input.tenantId)) throw new AccessDenied("missing incident:write");
  const note = input.note.trim().slice(0, 2000);
  if (!note) throw new Error("note required");
  return withScope({ tenantIds: [input.tenantId], grantIds: [partnerId], platform: false }, async (tx) => {
    if (input.incidentId) {
      const { incidents } = await import("@/db/schema");
      const [inc] = await tx.select({ id: incidents.id }).from(incidents).where(and(eq(incidents.id, input.incidentId), eq(incidents.tenantId, input.tenantId)));
      if (!inc) throw new AccessDenied("incident");
    }
    const [row] = await tx
      .insert(partnerEscalations)
      .values({
        tenantId: input.tenantId,
        partnerTenantId: partnerId,
        incidentId: input.incidentId || null,
        note,
        createdBy: ctx.principal.userId,
      })
      .returning();
    await audit(tx, {
      ...actor(ctx),
      tenantId: input.tenantId,
      action: "partner.escalate",
      targetType: "partner_escalation",
      targetId: row!.id,
      detail: { partnerId, incidentId: input.incidentId ?? null },
    });
    return row!;
  });
}

export async function listPartnerEscalations(ctx: AccessContext, partnerId: string) {
  if (partnerAnalystHome(ctx) !== partnerId && !(ctx.isPlatform && can(ctx, "mssp:read"))) throw new AccessDenied("partner report");
  const childIds = ctx.tenants.filter((t) => t.parentId === partnerId).map((t) => t.id);
  if (!childIds.length) return [];
  return withScope({ tenantIds: childIds, grantIds: partnerAnalystHome(ctx) ? [partnerId] : childIds, platform: ctx.isPlatform }, (tx) =>
    tx
      .select({
        id: partnerEscalations.id,
        tenantId: partnerEscalations.tenantId,
        note: partnerEscalations.note,
        createdAt: partnerEscalations.createdAt,
        customer: tenants.name,
      })
      .from(partnerEscalations)
      .innerJoin(tenants, eq(tenants.id, partnerEscalations.tenantId))
      .where(eq(partnerEscalations.partnerTenantId, partnerId))
      .orderBy(desc(partnerEscalations.createdAt))
      .limit(20),
  );
}
