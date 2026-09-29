/**
 * Partner hierarchy: consent, RLS, and the onboarding wizard.
 * Runs against a migrated database. Fresh tenants only.
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray, like } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, onboardingDrafts, partnerConsents, playbooks, reports, roleAssignments, roles, tenants, user } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { withScope } from "@/db/scope";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { BUILTIN_ROLES } from "@/lib/auth/permissions";
import { AccessDenied } from "@/lib/services/common";
import { listAlerts } from "@/lib/services/alerts";
import { quoteFor } from "@/lib/services/billing";
import { finishOnboarding, OnboardingError, saveOnboardingStep, startOnboarding } from "@/lib/services/onboarding";
import {
  PARTNER_CONSENT_STATEMENT, PARTNER_REVENUE_SHARE_BPS, cobrandLabel, escalateToSoc, grantPartnerCustomer,
  listPartnerEscalations, partnerCommercialReport, revenueShareCents, revokePartnerAccess, setPartnerBrand,
} from "@/lib/services/partner";
import { generateReport } from "@/lib/services/reports";

const stamp = `p28${randomUUID().slice(0, 8)}`;
const tenantIds: string[] = [];
const userIds: string[] = [];

async function asUser(id: string): Promise<AccessContext> {
  const [row] = await adminDb().select().from(user).where(eq(user.id, id));
  if (!row) throw new Error(`missing user ${id}`);
  return resolveAccess({ userId: row.id, name: row.name, email: row.email, isBreakGlass: row.isBreakGlass });
}

async function addUser(id: string, name: string, roleKey: string, tenantId: string) {
  await adminDb().insert(user).values({ id, name, email: `${id}@example.invalid`, emailVerified: true });
  userIds.push(id);
  await adminDb().insert(roleAssignments).values({ userId: id, roleKey, tenantId });
}

async function addPartner(name: string, slug: string) {
  const [row] = await adminDb().insert(tenants).values({
    name, slug, kind: "partner", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS,
  }).returning();
  tenantIds.push(row!.id);
  return row!;
}

async function addAlert(tenantId: string, externalId: string) {
  await adminDb().insert(alerts).values({
    tenantId, source: "partner-proof", externalId, title: "Partner isolation proof", severity: "low", occurredAt: new Date(),
  });
}

async function visibleAlerts(partnerId: string, ids: string[]) {
  return withScope({ tenantIds: ids, grantIds: [partnerId], platform: false }, (tx) =>
    tx.select({ tenantId: alerts.tenantId }).from(alerts).where(inArray(alerts.tenantId, ids)),
  );
}

async function cleanup() {
  if (userIds.length) await adminDb().delete(onboardingDrafts).where(inArray(onboardingDrafts.ownerUserId, userIds));
  const owned = tenantIds.length
    ? await adminDb().select({ id: tenants.id, kind: tenants.kind }).from(tenants).where(inArray(tenants.id, tenantIds))
    : [];
  const customers = owned.filter((row) => row.kind !== "partner").map((row) => row.id);
  const partners = owned.filter((row) => row.kind === "partner").map((row) => row.id);
  if (customers.length) await adminDb().delete(tenants).where(inArray(tenants.id, customers));
  if (partners.length) await adminDb().delete(tenants).where(inArray(tenants.id, partners));
  const leaked = await adminDb().select({ id: tenants.id, kind: tenants.kind }).from(tenants).where(like(tenants.slug, `${stamp}%`));
  const leakedCustomers = leaked.filter((row) => row.kind !== "partner").map((row) => row.id);
  const leakedPartners = leaked.filter((row) => row.kind === "partner").map((row) => row.id);
  if (leakedCustomers.length) await adminDb().delete(tenants).where(inArray(tenants.id, leakedCustomers));
  if (leakedPartners.length) await adminDb().delete(tenants).where(inArray(tenants.id, leakedPartners));
  if (userIds.length) await adminDb().delete(user).where(inArray(user.id, userIds));
}

beforeAll(async () => {
  for (const role of BUILTIN_ROLES.filter((item) => item.key.startsWith("partner_"))) {
    await adminDb().insert(roles).values({
      key: role.key, name: role.name, description: role.description, scope: role.scope, permissions: [...role.permissions], builtin: true,
    }).onConflictDoUpdate({
      target: roles.key,
      set: { name: role.name, description: role.description, scope: role.scope, permissions: [...role.permissions], builtin: true },
    });
  }
});

afterAll(cleanup);

describe("partner isolation", () => {
  it("hides the other partner's customer even when the id is supplied", async () => {
    const partnerA = await addPartner("River IT", `${stamp}-river`);
    const partnerB = await addPartner("Desert IT", `${stamp}-desert`);
    const adminAId = `${stamp}-admin-a`;
    const adminBId = `${stamp}-admin-b`;
    const customerUserId = `${stamp}-cust`;
    await addUser(adminAId, "River Admin", "partner_admin", partnerA.id);
    await addUser(adminBId, "Desert Admin", "partner_admin", partnerB.id);
    const adminA = await asUser(adminAId);
    const adminB = await asUser(adminBId);

    const custA = await grantPartnerCustomer(adminA, partnerA.id, { name: "Creek Clinic", slug: `${stamp}-creek`, sectors: ["HEALTHCARE"], deploymentMode: "shared" });
    const custB = await grantPartnerCustomer(adminB, partnerB.id, { name: "Dune Clinic", slug: `${stamp}-dune`, sectors: ["HEALTHCARE"], deploymentMode: "shared" });
    tenantIds.push(custA.id, custB.id);
    const [hidden] = await adminDb().insert(tenants).values({
      name: "Hidden Clinic", slug: `${stamp}-hidden`, kind: "customer", parentId: partnerA.id, sectors: ["HEALTHCARE"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS,
    }).returning();
    tenantIds.push(hidden!.id);

    const [consent] = await adminDb().select().from(partnerConsents).where(and(eq(partnerConsents.customerTenantId, custA.id), eq(partnerConsents.partnerTenantId, partnerA.id)));
    expect(consent?.statement).toBe(PARTNER_CONSENT_STATEMENT);
    expect(consent?.consentedBy).toBe(adminAId);
    expect(consent?.revokedAt).toBeNull();
    const hiddenConsent = await adminDb().select().from(partnerConsents).where(eq(partnerConsents.customerTenantId, hidden!.id));
    expect(hiddenConsent).toHaveLength(0);

    await addAlert(custA.id, `${stamp}-a`);
    await addAlert(custB.id, `${stamp}-b`);
    await addAlert(hidden!.id, `${stamp}-h`);
    await addUser(customerUserId, "Creek Admin", "customer_admin", custA.id);

    const seenA = await asUser(adminAId);
    expect(seenA.tenantIds).toEqual(expect.arrayContaining([partnerA.id, custA.id]));
    expect(seenA.tenantIds).not.toContain(custB.id);
    expect(seenA.tenantIds).not.toContain(hidden!.id);
    const listed = await listAlerts(seenA, {});
    expect(listed.rows.length).toBeGreaterThan(0);
    expect(new Set(listed.rows.map((row) => row.tenantId))).toEqual(new Set([custA.id]));

    const stuffed = await visibleAlerts(partnerA.id, [custA.id, custB.id, hidden!.id]);
    expect(new Set(stuffed.map((row) => row.tenantId))).toEqual(new Set([custA.id]));

    const seenB = await asUser(adminBId);
    expect(seenB.tenantIds).not.toContain(custA.id);
    const listedB = await listAlerts(seenB, {});
    expect(new Set(listedB.rows.map((row) => row.tenantId))).toEqual(new Set([custB.id]));

    const customer = await asUser(customerUserId);
    expect(customer.tenantIds).toEqual([custA.id]);
    const own = await listAlerts(customer, {});
    expect(own.rows.map((row) => row.tenantId)).toEqual([custA.id]);

    const platform = await withScope({ tenantIds: [custA.id, custB.id], grantIds: [custA.id, custB.id], platform: true }, (tx) =>
      tx.select({ tenantId: alerts.tenantId }).from(alerts).where(inArray(alerts.tenantId, [custA.id, custB.id])),
    );
    expect(new Set(platform.map((row) => row.tenantId))).toEqual(new Set([custA.id, custB.id]));

    await revokePartnerAccess(seenA, custA.id);
    const after = await asUser(adminAId);
    expect(after.tenantIds).not.toContain(custA.id);
    expect(await visibleAlerts(partnerA.id, [custA.id, custB.id, hidden!.id])).toEqual([]);
    const still = await listAlerts(await asUser(customerUserId), {});
    expect(still.rows.map((row) => row.tenantId)).toEqual([custA.id]);
  });
});

describe("partner onboarding", () => {
  it("records consent and co-brand when the provider finishes setup", async () => {
    const partner = await addPartner("River IT", `${stamp}-wizard`);
    const adminId = `${stamp}-wizard-admin`;
    const analystId = `${stamp}-wizard-analyst`;
    await addUser(adminId, "River Admin", "partner_admin", partner.id);
    await addUser(analystId, "River Analyst", "partner_analyst", partner.id);
    const ctx = await asUser(adminId);
    const draft = await startOnboarding(ctx);
    const org = {
      name: "Creek Clinic",
      abn: "51824753556",
      oricIcn: "",
      orgType: "accho",
      sectors: ["HEALTHCARE"],
      headcount: "12",
      locations: [{ name: "Townsville", remote: "remote", link: "low" }],
    };
    const contacts = {
      primaryName: "Alex Reed",
      primaryChannel: "phone",
      primaryValue: "0412000111",
      afterHoursName: "Sam Lee",
      afterHoursChannel: "sms",
      afterHoursValue: "0412000222",
      boardName: "Jo King",
      boardChannel: "email",
      boardValue: "jo@example.invalid",
      summaryEmail: `board-${stamp}@example.invalid`,
    };
    await saveOnboardingStep(ctx, draft.id, "org", org);
    await saveOnboardingStep(ctx, draft.id, "contacts", contacts);
    await saveOnboardingStep(ctx, draft.id, "stack", { identity: "other", accounting: "Xero", itProvider: "River IT" });
    await saveOnboardingStep(ctx, draft.id, "connect", { azureTenantId: "", domains: ["creek.example"] });
    await saveOnboardingStep(ctx, draft.id, "governance", { choice: "most_protective" });
    await saveOnboardingStep(ctx, draft.id, "plan", { tier: "essentials", nonprofit: "no" });

    await expect(finishOnboarding(ctx, draft.id)).rejects.toBeInstanceOf(OnboardingError);
    const [open] = await adminDb().select().from(onboardingDrafts).where(eq(onboardingDrafts.id, draft.id));
    expect(open?.tenantId).toBeNull();

    const done = await finishOnboarding(ctx, draft.id, { partnerConsent: true });
    tenantIds.push(done.tenantId);
    const [created] = await adminDb().select().from(tenants).where(eq(tenants.id, done.tenantId));
    expect(created).toMatchObject({ kind: "customer", parentId: partner.id });
    const [consent] = await adminDb().select().from(partnerConsents).where(eq(partnerConsents.customerTenantId, done.tenantId));
    expect(consent).toMatchObject({ partnerTenantId: partner.id, consentedBy: adminId, statement: PARTNER_CONSENT_STATEMENT, revokedAt: null });

    const [welcome] = await adminDb().select().from(reports).where(eq(reports.id, done.reportId));
    expect(welcome?.content.cobrand).toBe("River IT with blakSOC");
    const books = await adminDb().select().from(playbooks).where(eq(playbooks.tenantId, done.tenantId));
    expect(books.some((book) => book.name === "Suspected BEC" && book.enabled === false)).toBe(true);

    const fresh = await asUser(adminId);
    expect(fresh.tenantIds).toContain(done.tenantId);
    const [commercial] = await partnerCommercialReport(fresh, partner.id);
    expect(commercial?.id).toBe(done.tenantId);
    expect(commercial?.shareBps).toBe(PARTNER_REVENUE_SHARE_BPS);
    expect(commercial?.shareExGstCents).toBe(revenueShareCents(commercial!.exGstCents));
    const quote = await quoteFor(fresh, done.tenantId);
    if (quote && !("error" in quote)) {
      expect(commercial?.priceSource).toBe("quote");
      expect(commercial?.exGstCents).toBe(quote.exGstCents);
    } else {
      expect(commercial?.priceSource).toBe("list");
      expect(commercial?.exGstCents).toBe(45_000);
      expect(commercial?.shareExGstCents).toBe(9_000);
    }

    const branded = await setPartnerBrand(fresh, partner.id, " River ");
    expect(branded.cobrand).toBe("River with blakSOC");
    expect(await cobrandLabel(done.tenantId)).toBe("River with blakSOC");
    const report = await generateReport(fresh, done.tenantId, "sla");
    expect(report.content.cobrand).toBe("River with blakSOC");

    const analyst = await asUser(analystId);
    await expect(partnerCommercialReport(analyst, partner.id)).rejects.toBeInstanceOf(AccessDenied);
    const note = "Please look at the new clinic mailbox.";
    const escalation = await escalateToSoc(analyst, { tenantId: done.tenantId, note });
    const notes = await listPartnerEscalations(fresh, partner.id);
    expect(notes.some((row) => row.id === escalation.id && row.note === note && row.tenantId === done.tenantId)).toBe(true);
  });
});
