import { and, desc, eq, gte, inArray, isNull, notInArray, sql } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { alerts, approvals, assets, incidents, tenants, user, wallboardLinks } from "@/db/schema";
import { withScope } from "@/db/scope";
import { audit } from "@/lib/audit";
import { AccessDenied, can, dbScope, resolveAccess, type AccessContext } from "@/lib/auth/access";
import { env } from "@/lib/env";
import { signWallboardToken, verifyWallboardToken } from "@/lib/wallboard/token";
import { WALLBOARD_EXPIRY_DAYS, type WallboardExpiryDays, type WallboardSnapshot } from "@/lib/wallboard/types";

/** Sharing operational data requires a platform manager, rather than any dashboard reader. */
export function canManageWallboardLinks(ctx: AccessContext): boolean {
  if (ctx.principal.kind === "service") return false;
  const permissions = new Set(ctx.grants.filter((g) => g.tenantId === null).flatMap((g) => [...g.permissions]));
  return permissions.has("dashboard:read") && (permissions.has("response:approve") || permissions.has("user:manage"));
}

function assertManager(ctx: AccessContext) {
  if (!canManageWallboardLinks(ctx)) throw new AccessDenied("a platform dashboard manager is required");
}

const realCustomer = sql`coalesce((${tenants.settings}->>'training')::boolean, false) = false`;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function customerScope(ctx: AccessContext, requested?: readonly string[]): string[] {
  if (!can(ctx, "dashboard:read")) throw new AccessDenied("missing dashboard:read");
  const customers = ctx.tenants.filter((t) => t.kind === "customer" && can(ctx, "dashboard:read", t.id));
  if (requested && requested.some((id) => !UUID.test(id) || !customers.some((t) => t.id === id))) throw new AccessDenied("customer scope is not permitted");
  return [...new Set(requested ?? customers.map((t) => t.id))];
}

/** Returns aggregate operational data only: no alert titles, raw events or analyst details. */
export async function wallboardSnapshot(ctx: AccessContext, tenantIds?: readonly string[], linkExpiresAt: Date | null = null): Promise<WallboardSnapshot> {
  const selected = customerScope(ctx, tenantIds);
  const now = new Date();
  const firstHour = new Date(now);
  firstHour.setUTCMinutes(0, 0, 0);
  firstHour.setUTCHours(firstHour.getUTCHours() - 23);
  const empty: WallboardSnapshot = {
    generatedAt: now.toISOString(), scopeName: "All customers", customerCount: 0,
    counts: { openAlerts: 0, criticalAlerts: 0, awaitingTriage: 0, unassigned: 0, activeIncidents: 0, overdueIncidents: 0, pendingApprovals: 0 },
    activity: Array.from({ length: 24 }, (_, hour) => ({ hour: new Date(firstHour.getTime() + hour * 3600_000).toISOString(), count: 0 })),
    customers: [], incidentSummary: [], linkExpiresAt: linkExpiresAt?.toISOString() ?? null,
  };
  if (!selected.length) return empty;
  return withScope(dbScope(ctx, selected, false), async (tx) => {
    const customerRows = await tx.select({ id: tenants.id, name: tenants.name }).from(tenants)
      .where(and(inArray(tenants.id, selected), eq(tenants.kind, "customer"), eq(tenants.status, "active"), realCustomer));
    const ids = customerRows.map((t) => t.id);
    if (!ids.length) return empty;
    const open = and(inArray(alerts.tenantId, ids), eq(alerts.lane, "active"), notInArray(alerts.status, ["RESOLVED", "FALSE_POSITIVE"]));
    const alertCounts = await tx.select({
      tenantId: alerts.tenantId,
      openAlerts: sql<number>`count(*)::int`,
      criticalAlerts: sql<number>`count(*) filter (where ${alerts.severity} = 'critical' or ${alerts.riskScore} >= 80)::int`,
      awaitingTriage: sql<number>`count(*) filter (where ${alerts.status} = 'NEW')::int`,
      unassigned: sql<number>`count(*) filter (where ${alerts.assigneeId} is null)::int`,
      healthAlerts: sql<number>`count(*) filter (where ${alerts.source} = 'health')::int`,
      risk: sql<number>`coalesce(max(${alerts.riskScore}), 0)::int`,
    }).from(alerts).where(open).groupBy(alerts.tenantId);
    const active = and(inArray(incidents.tenantId, ids), notInArray(incidents.status, ["CLOSED"]));
    const incidentCounts = await tx.select({
      tenantId: incidents.tenantId, activeIncidents: sql<number>`count(*)::int`,
      overdueIncidents: sql<number>`count(*) filter (where ${incidents.slaDueAt} < ${now.toISOString()} and ${incidents.status} not in ('CONTAINED','ERADICATED','RECOVERED'))::int`,
    }).from(incidents).where(active).groupBy(incidents.tenantId);
    const endpointCounts = await tx.select({
      tenantId: assets.tenantId, endpoints: sql<number>`count(*)::int`,
      offlineEndpoints: sql<number>`count(*) filter (where ${assets.agentStatus} is distinct from 'active')::int`,
    }).from(assets).where(and(inArray(assets.tenantId, ids), inArray(assets.kind, ["endpoint", "server"]))).groupBy(assets.tenantId);
    const [pending] = await tx.select({ n: sql<number>`count(*)::int` }).from(approvals)
      .where(and(inArray(approvals.tenantId, ids), eq(approvals.status, "PENDING")));
    const hourly = await tx.select({ hour: sql<string>`to_char(date_trunc('hour', ${alerts.occurredAt} at time zone 'UTC'), 'YYYY-MM-DD"T"HH24:MI:SS".000Z"')`, count: sql<number>`count(*)::int` })
      .from(alerts).where(and(inArray(alerts.tenantId, ids), gte(alerts.occurredAt, firstHour), sql`${alerts.occurredAt} <= ${now.toISOString()}`))
      .groupBy(sql`1`);
    const incidentRows = await tx.select({ id: incidents.id, ref: incidents.ref, severity: incidents.severity, status: incidents.status, tenantName: tenants.name, slaDueAt: incidents.slaDueAt })
      .from(incidents).innerJoin(tenants, eq(tenants.id, incidents.tenantId)).where(active).orderBy(desc(incidents.riskScore), desc(incidents.updatedAt)).limit(4);
    const byAlerts = new Map(alertCounts.map((r) => [r.tenantId, r]));
    const byIncidents = new Map(incidentCounts.map((r) => [r.tenantId, r]));
    const byEndpoints = new Map(endpointCounts.map((r) => [r.tenantId, r]));
    const customers = customerRows.map((t) => ({
      id: t.id, name: t.name, openAlerts: byAlerts.get(t.id)?.openAlerts ?? 0,
      criticalAlerts: byAlerts.get(t.id)?.criticalAlerts ?? 0, activeIncidents: byIncidents.get(t.id)?.activeIncidents ?? 0,
      endpoints: byEndpoints.get(t.id)?.endpoints ?? 0, offlineEndpoints: byEndpoints.get(t.id)?.offlineEndpoints ?? 0,
      healthAlerts: byAlerts.get(t.id)?.healthAlerts ?? 0, risk: byAlerts.get(t.id)?.risk ?? 0,
    })).sort((a, b) => b.risk - a.risk || b.openAlerts - a.openAlerts || a.name.localeCompare(b.name));
    const hourlyCounts = new Map(hourly.map((r) => [r.hour, r.count]));
    return {
      ...empty, customerCount: customers.length, scopeName: customers.length === 1 ? customers[0]!.name : `${customers.length} customers`, customers,
      counts: {
        openAlerts: alertCounts.reduce((n, r) => n + r.openAlerts, 0), criticalAlerts: alertCounts.reduce((n, r) => n + r.criticalAlerts, 0),
        awaitingTriage: alertCounts.reduce((n, r) => n + r.awaitingTriage, 0), unassigned: alertCounts.reduce((n, r) => n + r.unassigned, 0),
        activeIncidents: incidentCounts.reduce((n, r) => n + r.activeIncidents, 0), overdueIncidents: incidentCounts.reduce((n, r) => n + r.overdueIncidents, 0), pendingApprovals: pending?.n ?? 0,
      },
      activity: empty.activity.map((bucket) => ({ ...bucket, count: hourlyCounts.get(bucket.hour) ?? 0 })),
      incidentSummary: incidentRows.map((r) => ({ ...r, slaDueAt: r.slaDueAt?.toISOString() ?? null })),
    };
  });
}

export async function createWallboardLink(ctx: AccessContext, input: { name: string; tenantIds: readonly string[]; expiresInDays: WallboardExpiryDays }) {
  assertManager(ctx);
  if (!input || typeof input !== "object" || typeof input.name !== "string") throw new Error("Enter a display name.");
  if (!Array.isArray(input.tenantIds) || input.tenantIds.some((id) => typeof id !== "string" || !UUID.test(id))) throw new Error("Choose valid customers.");
  const name = input.name.trim();
  if (!name || name.length > 80) throw new Error("Name must be 1–80 characters.");
  if (!(WALLBOARD_EXPIRY_DAYS as readonly number[]).includes(input.expiresInDays)) throw new Error("Choose a supported link lifetime.");
  const ids = customerScope(ctx, input.tenantIds);
  if (!ids.length) throw new Error("Choose at least one customer.");
  const expiresAt = new Date(Date.now() + input.expiresInDays * 86_400_000);
  const id = await withScope(dbScope(ctx, ids, true), async (tx) => {
    const customerRows = await tx.select({ id: tenants.id }).from(tenants).where(and(inArray(tenants.id, ids), eq(tenants.status, "active"), realCustomer));
    if (customerRows.length !== ids.length) throw new AccessDenied("training or inactive customers cannot be shared");
    const [row] = await tx.insert(wallboardLinks).values({ name, tenantIds: ids, createdBy: ctx.principal.userId, expiresAt }).returning({ id: wallboardLinks.id });
    await audit(tx, { actorId: ctx.principal.userId, actorKind: "user", tenantId: null, action: "wallboard.create", targetType: "wallboard_link", targetId: row!.id, detail: { name, tenantIds: ids, expiresAt: expiresAt.toISOString() } });
    return row!.id;
  });
  const url = new URL("/wallboard", env().APP_URL);
  url.searchParams.set("token", signWallboardToken(id, expiresAt, env().BETTER_AUTH_SECRET));
  return { id, url: url.toString(), expiresAt: expiresAt.toISOString() };
}

export async function listWallboardLinks(ctx: AccessContext) {
  assertManager(ctx);
  return withScope({ tenantIds: [], platform: true }, async (tx) => {
    const rows = await tx.select().from(wallboardLinks).orderBy(desc(wallboardLinks.createdAt)).limit(100);
    return rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString(), expiresAt: row.expiresAt.toISOString(), revokedAt: row.revokedAt?.toISOString() ?? null }));
  });
}

export async function revokeWallboardLink(ctx: AccessContext, id: string): Promise<void> {
  assertManager(ctx);
  if (!UUID.test(id)) throw new AccessDenied("display link not found");
  await withScope({ tenantIds: [], platform: true }, async (tx) => {
    const [row] = await tx.update(wallboardLinks).set({ revokedAt: new Date() }).where(and(eq(wallboardLinks.id, id), isNull(wallboardLinks.revokedAt))).returning({ id: wallboardLinks.id, name: wallboardLinks.name });
    if (row) await audit(tx, { actorId: ctx.principal.userId, actorKind: "user", tenantId: null, action: "wallboard.revoke", targetType: "wallboard_link", targetId: id, detail: { name: row.name } });
  });
}

/** Re-resolve the issuing user's current authority on every page load and refresh. */
export async function signedWallboardSnapshot(token: string): Promise<WallboardSnapshot | null> {
  const parsed = verifyWallboardToken(token, env().BETTER_AUTH_SECRET);
  if (!parsed) return null;
  const [row] = await systemDb().select({ link: wallboardLinks, issuer: user }).from(wallboardLinks)
    .innerJoin(user, eq(user.id, wallboardLinks.createdBy)).where(eq(wallboardLinks.id, parsed.id));
  if (!row || row.link.revokedAt || row.link.expiresAt <= new Date() || row.link.expiresAt.getTime() !== parsed.expiresAt.getTime() || row.issuer.disabled) return null;
  if (row.issuer.isBreakGlass && !row.issuer.twoFactorEnabled && env().BREAK_GLASS_REQUIRE_MFA === "true") return null;
  const ctx = await resolveAccess({ userId: row.issuer.id, name: row.issuer.name, email: row.issuer.email, isBreakGlass: row.issuer.isBreakGlass });
  if (!canManageWallboardLinks(ctx) || !row.link.tenantIds.length) return null;
  try {
    const snapshot = await wallboardSnapshot(ctx, row.link.tenantIds, row.link.expiresAt);
    if (snapshot.customerCount !== row.link.tenantIds.length) return null;
    return snapshot;
  } catch (err) {
    if (err instanceof AccessDenied) return null;
    throw err;
  }
}
