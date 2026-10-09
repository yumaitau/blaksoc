import { and, eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, assets, auditLog, incidents, roleAssignments, roles, tenants, user, wallboardLinks } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { AccessDenied, resolveAccess, type AccessContext } from "@/lib/auth/access";
import { env } from "@/lib/env";
import { createWallboardLink, listWallboardLinks, revokeWallboardLink, signedWallboardSnapshot, wallboardSnapshot } from "@/lib/services/wallboard";
import { signWallboardToken } from "@/lib/wallboard/token";

const stamp = `wallboard-${Date.now()}`;
const issuerId = `${stamp}-issuer`;
const roleKey = `${stamp}-manager`;
let a: string, b: string, training: string;
let ctx: AccessContext;
const tokens = new Map<string, string>();

async function link(tenantIds = [a]) {
  const result = await createWallboardLink(ctx, { name: "Office TV", tenantIds, expiresInDays: 7 });
  const token = new URL(result.url).searchParams.get("token")!;
  tokens.set(result.id, token);
  return { ...result, token };
}

beforeAll(async () => {
  await adminDb().insert(user).values({ id: issuerId, name: "Private analyst name", email: `${issuerId}@example.invalid`, emailVerified: true });
  await adminDb().insert(roles).values({ key: roleKey, name: "TV manager test", scope: "platform", permissions: ["dashboard:read", "response:approve"] });
  await adminDb().insert(roleAssignments).values({ userId: issuerId, roleKey });
  const rows = await adminDb().insert(tenants).values([
    { name: "TV customer A", slug: `${stamp}-a`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
    { name: "TV customer B", slug: `${stamp}-b`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
    { name: "TV training", slug: `${stamp}-training`, kind: "customer", settings: { ...DEFAULT_TENANT_SETTINGS, training: true } },
  ]).returning();
  [a, b, training] = rows.map((r) => r.id) as [string, string, string];
  ctx = await resolveAccess({ userId: issuerId, name: "Private analyst name", email: `${issuerId}@example.invalid`, isBreakGlass: false });
  await adminDb().insert(alerts).values([
    { tenantId: a, source: "health", externalId: `${stamp}-active`, title: "PRIVATE ALERT TITLE", severity: "critical", riskScore: 95, raw: { private: "PRIVATE RAW TELEMETRY" }, occurredAt: new Date() },
    { tenantId: a, source: "test", externalId: `${stamp}-passive`, title: "PRIVATE PASSIVE TITLE", severity: "critical", riskScore: 99, lane: "passive", occurredAt: new Date() },
    { tenantId: b, source: "test", externalId: `${stamp}-other`, title: "PRIVATE OTHER TITLE", severity: "critical", occurredAt: new Date() },
  ]);
  await adminDb().insert(incidents).values(Array.from({ length: 10 }, (_, i) => ({ tenantId: a, title: `PRIVATE INCIDENT ${i}`, severity: "high" as const, riskScore: i, slaDueAt: new Date(Date.now() - 3600_000) })));
  await adminDb().insert(assets).values([
    { tenantId: a, name: "Private active endpoint", kind: "endpoint", agentStatus: "active" },
    { tenantId: a, name: "Private offline endpoint", kind: "endpoint", agentStatus: "disconnected" },
    { tenantId: a, name: "Private unknown endpoint", kind: "server", agentStatus: null },
  ]);
});

afterAll(async () => {
  await adminDb().delete(wallboardLinks).where(eq(wallboardLinks.createdBy, issuerId));
  if (a) await adminDb().delete(tenants).where(inArray(tenants.id, [a, b, training]));
  await adminDb().delete(user).where(eq(user.id, issuerId));
  await adminDb().delete(roles).where(eq(roles.key, roleKey));
});

describe("office wallboard", () => {
  it("counts all active incidents and excludes passive alerts and private details", async () => {
    const created = await link();
    const data = await signedWallboardSnapshot(created.token);
    expect(data?.counts).toMatchObject({ openAlerts: 1, criticalAlerts: 1, activeIncidents: 10, overdueIncidents: 10 });
    expect(data?.customers.map((t) => t.id)).toEqual([a]);
    expect(data?.incidentSummary).toHaveLength(4);
    expect(data?.activity).toHaveLength(24);
    expect(data?.activity.reduce((n, bucket) => n + bucket.count, 0)).toBe(2);
    expect(data?.customers[0]).toMatchObject({ endpoints: 3, offlineEndpoints: 2 });
    expect(JSON.stringify(data)).not.toMatch(/PRIVATE|Private analyst|example\.invalid|raw|title|ownerName/);
    expect(data?.linkExpiresAt).toBe(created.expiresAt);
  });

  it("rejects training and foreign scopes, and requires management authority", async () => {
    await expect(link([training])).rejects.toBeInstanceOf(AccessDenied);
    const reader = { ...ctx, grants: [{ roleKey: "reader", tenantId: null, permissions: new Set(["dashboard:read"] as const) }] };
    await expect(createWallboardLink(reader, { name: "reader", tenantIds: [a], expiresInDays: 1 })).rejects.toBeInstanceOf(AccessDenied);
    await expect(wallboardSnapshot({ ...ctx, tenantIds: [a], tenants: ctx.tenants.filter((t) => t.id === a) }, [b])).rejects.toBeInstanceOf(AccessDenied);
    expect((await wallboardSnapshot(ctx, [training])).customerCount).toBe(0);
  });

  it("persists the fixed scope and audits creation and revocation without the URL token", async () => {
    const created = await link();
    expect((await listWallboardLinks(ctx)).find((r) => r.id === created.id)?.tenantIds).toEqual([a]);
    await revokeWallboardLink(ctx, created.id);
    expect(await signedWallboardSnapshot(created.token)).toBeNull();
    const auditRows = await adminDb().select().from(auditLog).where(and(eq(auditLog.targetId, created.id), eq(auditLog.actorId, issuerId)));
    expect(auditRows.map((r) => r.action).sort()).toEqual(["wallboard.create", "wallboard.revoke"]);
    expect(JSON.stringify(auditRows)).not.toContain(created.token);
  });

  it("rejects tampering, expiry and changed persisted expiry", async () => {
    const created = await link();
    expect(await signedWallboardSnapshot(`${created.token}x`)).toBeNull();
    const expired = signWallboardToken(created.id, new Date(Date.now() - 1), env().BETTER_AUTH_SECRET);
    expect(await signedWallboardSnapshot(expired)).toBeNull();
    await adminDb().update(wallboardLinks).set({ expiresAt: new Date(Date.now() + 3600_000) }).where(eq(wallboardLinks.id, created.id));
    expect(await signedWallboardSnapshot(created.token)).toBeNull();
  });

  it("stops a live link when its issuer is disabled or loses manager permission", async () => {
    const created = await link();
    await adminDb().update(user).set({ disabled: true }).where(eq(user.id, issuerId));
    try { expect(await signedWallboardSnapshot(created.token)).toBeNull(); }
    finally { await adminDb().update(user).set({ disabled: false }).where(eq(user.id, issuerId)); }
    await adminDb().update(roles).set({ permissions: ["dashboard:read"] }).where(eq(roles.key, roleKey));
    try { expect(await signedWallboardSnapshot(created.token)).toBeNull(); }
    finally { await adminDb().update(roles).set({ permissions: ["dashboard:read", "response:approve"] }).where(eq(roles.key, roleKey)); }
    expect(await signedWallboardSnapshot(created.token)).not.toBeNull();
  });

  it("stops a link when a selected customer becomes inactive", async () => {
    const created = await link();
    await adminDb().update(tenants).set({ status: "suspended" }).where(eq(tenants.id, a));
    try { expect(await signedWallboardSnapshot(created.token)).toBeNull(); }
    finally { await adminDb().update(tenants).set({ status: "active" }).where(eq(tenants.id, a)); }
  });

  it("honours live break-glass MFA requirements", async () => {
    const created = await link();
    await adminDb().update(user).set({ isBreakGlass: true, twoFactorEnabled: false }).where(eq(user.id, issuerId));
    try {
      const snapshot = await signedWallboardSnapshot(created.token);
      if (env().BREAK_GLASS_REQUIRE_MFA === "true") expect(snapshot).toBeNull();
      else expect(snapshot).not.toBeNull();
      await adminDb().update(user).set({ twoFactorEnabled: true }).where(eq(user.id, issuerId));
      expect(await signedWallboardSnapshot(created.token)).not.toBeNull();
    } finally { await adminDb().update(user).set({ isBreakGlass: false, twoFactorEnabled: false }).where(eq(user.id, issuerId)); }
  });

  it("deleting the issuer also invalidates and deletes its links", async () => {
    const created = await link();
    await adminDb().delete(user).where(eq(user.id, issuerId));
    expect(await signedWallboardSnapshot(created.token)).toBeNull();
    expect(await adminDb().select().from(wallboardLinks).where(eq(wallboardLinks.id, created.id))).toHaveLength(0);
  });
});
