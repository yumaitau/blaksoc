import { createHmac, randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it, vi } from "vitest";
import { POST } from "@/app/api/ingest/wedgetail/[integrationId]/route";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { alerts, auditLog, integrations, observables, tenants } from "@/db/schema";
import { systemScope, type AccessContext } from "@/lib/auth/access";
import { secretAad } from "@/lib/connectors/instances";
import { decryptSecret } from "@/lib/crypto";
import { createWedgetailIntegration, listIntegrations, updateIntegration } from "@/lib/services/integrations";
import { WEDGETAIL_CREATED } from "../fixtures/wedgetail";

// No intel connector or outbound notification in these fictional tenants.
vi.mock("@/lib/connectors/instances", async (original) => ({ ...await original<typeof import("@/lib/connectors/instances")>(), intelProviderFor: async () => null }));
vi.mock("@/lib/events", () => ({ publish: vi.fn() }));
vi.mock("@/lib/soar/engine", () => ({ evaluateTriggers: vi.fn() }));
import { publish } from "@/lib/events";

const created: string[] = [];
function staff(tenantId: string): AccessContext {
  return { principal: { userId: "wedgetail-fictional-admin", name: "Fictional Admin", email: "admin@example.com", isBreakGlass: false }, isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions: new Set(["integration:manage", "integration:read"]) }], tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "fictional", name: "Fictional Clinic", kind: "customer" }] };
}
async function tenant() {
  const [row] = await adminDb().insert(tenants).values({ slug: `wedgetail-${randomUUID()}`, name: "Fictional Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!.id;
}
async function integration(tenantId: string) {
  return createWedgetailIntegration(staff(tenantId), { tenantId, name: "Wedgetail fictional install", config: { region: "ap-southeast-2" } });
}
function post(connection: { id: string; secret: string }, payload: unknown, timestamp = String(Math.floor(Date.now() / 1000))) {
  const body = JSON.stringify(payload);
  return POST(new Request(`https://soc.example.com/api/ingest/wedgetail/${connection.id}`, { method: "POST", body, headers: {
    "content-type": "application/json", "x-wedgetail-timestamp": timestamp,
    "x-wedgetail-signature": `v1=${createHmac("sha256", connection.secret).update(`${timestamp}.${body}`).digest("hex")}`,
  } }), { params: Promise.resolve({ integrationId: connection.id }) });
}
afterAll(async () => { if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created)); });

describe("Wedgetail webhook with RLS", () => {
  it("generates a bound encrypted secret once and refuses a shared or unauthorised integration", async () => {
    const a = await tenant(); const b = await tenant();
    await expect(createWedgetailIntegration(staff(a), { tenantId: b, name: "Forbidden", config: {} })).rejects.toThrow();
    await expect(createWedgetailIntegration({ ...staff(a), isPlatform: true, grants: [{ roleKey: "platform_admin", tenantId: null, permissions: new Set(["integration:manage"]) }] }, { tenantId: null, name: "Shared", config: {} })).rejects.toThrow(/one tenant/);
    const connection = await integration(a);
    expect(connection.secret.length).toBeGreaterThanOrEqual(32);
    expect(connection.ingestPath).toBe(`/api/ingest/wedgetail/${connection.id}`);
    const [saved] = await adminDb().select().from(integrations).where(eq(integrations.id, connection.id));
    expect(saved!.secretCiphertext).not.toContain(connection.secret);
    expect(JSON.parse(decryptSecret(saved!.secretCiphertext!, secretAad(connection.id)))).toEqual({ signingSecret: connection.secret });
    expect(() => decryptSecret(saved!.secretCiphertext!, secretAad(randomUUID()))).toThrow();
    const listed = await listIntegrations(staff(a));
    expect(listed.find((r) => r.id === connection.id)).not.toHaveProperty("secretCiphertext");
    expect(JSON.stringify(listed)).not.toContain(connection.secret);
  });

  it("uses only the integration tenant, refreshes concurrent replays, and enforces RLS", async () => {
    const a = await tenant(); const b = await tenant();
    const installA = await integration(a); const installB = await integration(b);
    const body = { ...WEDGETAIL_CREATED, tenant: { id: b }, alert: { ...WEDGETAIL_CREATED.alert, tenantId: b } };
    const responses = await Promise.all(Array.from({ length: 3 }, () => post(installA, body)));
    expect(responses.map((r) => r.status).sort()).toEqual([200, 200, 202]);
    expect((await post(installB, WEDGETAIL_CREATED)).status).toBe(202);
    const changed = { ...WEDGETAIL_CREATED, alert: { ...WEDGETAIL_CREATED.alert, ruleTitle: "Updated fictional detection", severity: "critical", eventCount: 3 } };
    expect((await post(installA, changed)).status).toBe(200);
    const rows = await withScope(systemScope(a), (tx) => tx.select().from(alerts));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tenantId: a, integrationId: installA.id, title: "Updated fictional detection", severity: "critical", externalId: WEDGETAIL_CREATED.alert.id, source: "wedgetail" });
    expect(rows[0]!.riskScore).toBeGreaterThan(0);
    expect(rows[0]!.ocsf).toMatchObject({ class_uid: 2004, metadata: { tenant_uid: a, product: { name: "Wedgetail" } } });
    const invisible = await withScope(systemScope(a), (tx) => tx.select().from(alerts).where(eq(alerts.tenantId, b)));
    expect(invisible).toEqual([]);
    await expect(withScope(systemScope(a), (tx) => tx.insert(alerts).values({ tenantId: b, source: "wedgetail", externalId: "forbidden-write", title: "Forbidden", severity: "low", occurredAt: new Date() }))).rejects.toThrow();
    const ips = await withScope(systemScope(a), (tx) => tx.select().from(observables).where(eq(observables.type, "ipv4")));
    expect(ips).toContainEqual(expect.objectContaining({ value: "198.51.100.10", sightings: 1 }));
    const [health] = await withScope(systemScope(a), (tx) => tx.select().from(integrations).where(eq(integrations.id, installA.id)));
    expect(health!.health).toMatchObject({ detail: { created: 1, duplicate: 3, unrouted: 0, rejected: 0, lastReceivedAt: expect.any(String) } });
  });

  it("audits status changes, ignores old/repeated updates and cannot change another install", async () => {
    const a = await tenant(); const b = await tenant();
    const install = await integration(a); const other = await integration(b); const sameTenantOther = await integration(a);
    await post(install, WEDGETAIL_CREATED);
    const status = (value: string, at: number) => ({ type: "wedgetail.alert.updated", alert: { id: WEDGETAIL_CREATED.alert.id, status: value, updatedAt: new Date(at).toISOString() } });
    const now = Date.now();
    vi.mocked(publish).mockClear();
    expect((await post(other, status("closed", now))).status).toBe(409);
    expect((await post(sameTenantOther, status("closed", now))).status).toBe(409);
    for (const [value, expected, offset] of [["acknowledged", "TRIAGING", 0], ["closed_false_positive", "FALSE_POSITIVE", 1], ["new", "NEW", 2]] as const) {
      expect((await post(install, status(value, now + offset))).status).toBe(200);
      const [row] = await withScope(systemScope(a), (tx) => tx.select().from(alerts));
      expect(row!.status).toBe(expected);
    }
    await post(install, status("closed", now));
    await post(install, status("new", now + 2));
    // A creation retry refreshes the finding but preserves status and its sync watermark.
    await post(install, WEDGETAIL_CREATED);
    await post(install, status("closed", now + 1));
    const [row] = await withScope(systemScope(a), (tx) => tx.select().from(alerts));
    expect(row!.status).toBe("NEW");
    const audits = await withScope(systemScope(a), (tx) => tx.select().from(auditLog).where(and(eq(auditLog.targetId, row!.id), eq(auditLog.action, "alert.update"))));
    expect(audits).toHaveLength(3);
    expect(audits.every((r) => r.actorId === `wedgetail:${install.id}` && r.tenantId === a)).toBe(true);
    expect(publish).not.toHaveBeenCalled();
  });

  it("refuses invalid credentials, stale signatures, disabled installs and oversized bodies", async () => {
    const a = await tenant(); const install = await integration(a);
    expect((await post({ ...install, secret: "wrong" }, WEDGETAIL_CREATED)).status).toBe(401);
    expect((await post(install, WEDGETAIL_CREATED, String(Math.floor(Date.now() / 1000) - 301))).status).toBe(401);
    expect((await post(install, { padding: "x".repeat(262145) })).status).toBe(413);
    await updateIntegration(staff(a), install.id, { enabled: false });
    expect((await post(install, WEDGETAIL_CREATED)).status).toBe(404);
    expect((await post({ ...install, id: randomUUID() }, WEDGETAIL_CREATED)).status).toBe(404);
    expect(await withScope(systemScope(a), (tx) => tx.select().from(alerts))).toEqual([]);
  });
});
