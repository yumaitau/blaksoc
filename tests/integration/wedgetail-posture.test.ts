import { randomUUID } from "node:crypto";
import { eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { roleAssignments, roles, tenants, user, wedgetailPosture } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { complianceSignals } from "@/lib/services/compliance";
import { attackCoverage } from "@/lib/services/detections";
import { createWedgetailIntegration, updateIntegration } from "@/lib/services/integrations";
import { readWedgetailPosture, refreshWedgetailPosture, syncWedgetailPosture } from "@/lib/services/wedgetail-posture";
import { WedgetailApiError } from "@/lib/wedgetail/posture";
import { E8, ISM, MITRE, TOKEN } from "../fixtures/wedgetail-posture";

const stamp = `wt-posture-${Date.now()}`;
const userId = `${stamp}-lead`;
const roleKey = `${stamp}-role`;
let a: string, b: string, integrationId: string;
let lead: AccessContext;

function staff(tenantId: string, permissions = ["integration:manage", "integration:read"]): AccessContext {
  return { principal: { userId: `${stamp}-staff`, name: "Fictional Admin", email: "admin@example.com", isBreakGlass: false }, isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions: new Set(permissions as never[]) }], tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "fictional", name: "Fictional", kind: "customer" }] };
}
const ok = () => async (tool: string) => (tool === "ism_status" ? ISM : tool === "essential_eight_summary" ? E8 : MITRE);

beforeAll(async () => {
  const rows = await adminDb().insert(tenants).values([
    { name: "Posture A", slug: `${stamp}-a`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
    { name: "Posture B", slug: `${stamp}-b`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
  ]).returning();
  [a, b] = rows.map((r) => r.id) as [string, string];
  const created = await createWedgetailIntegration(staff(a), { tenantId: a, name: "Fictional install", config: { region: "ap-southeast-2" } });
  integrationId = created.id;
  await updateIntegration(staff(a), integrationId, { configPatch: { consoleUrl: "https://wedgetail.example.com" }, secrets: { mcpToken: TOKEN } });
  await adminDb().insert(user).values({ id: userId, name: "Fictional lead", email: `${userId}@example.invalid`, emailVerified: true });
  await adminDb().insert(roles).values({ key: roleKey, name: "Posture test", scope: "platform", permissions: ["alert:read", "report:read", "detection:read", "integration:read"] });
  await adminDb().insert(roleAssignments).values({ userId, roleKey });
  lead = await resolveAccess({ userId, name: "Fictional lead", email: `${userId}@example.invalid`, isBreakGlass: false });
});

afterAll(async () => {
  if (a) await adminDb().delete(tenants).where(inArray(tenants.id, [a, b]));
  await adminDb().delete(user).where(eq(user.id, userId));
  await adminDb().delete(roles).where(eq(roles.key, roleKey));
});

describe("Wedgetail posture pull", () => {
  it("stores a sanitised snapshot, waits until due and keeps it when a pull fails", async () => {
    const now = new Date();
    const first = await syncWedgetailPosture({ now, connect: ok });
    expect(first.pulled).toBeGreaterThanOrEqual(1);
    const [row] = await adminDb().select().from(wedgetailPosture).where(eq(wedgetailPosture.integrationId, integrationId));
    expect(row).toMatchObject({ tenantId: a, lastError: null, attempts: 0 });
    expect(row!.ism!.counts).toEqual({ met: 1, partial: 1, not_met: 1, not_applicable: 0 });
    expect(JSON.stringify(row!.ism)).not.toContain("CISO");
    expect(row!.mitre!.techniques.map((t) => t.id)).toContain("T1078");
    expect(row!.e8!.strategies.map((s) => [s.strategy, s.maturity])).toEqual([["mfa", 1], ["restrict_admin", 0]]);

    let called = false;
    await syncWedgetailPosture({ now: new Date(now.getTime() + 60_000), connect: () => async () => { called = true; return ISM; } });
    expect(called).toBe(false);

    const later = new Date(now.getTime() + 2 * 3600_000);
    const failed = await syncWedgetailPosture({ now: later, connect: () => async () => { throw new WedgetailApiError("Wedgetail refused the token (HTTP 401).", true); } });
    expect(failed.failed).toBeGreaterThanOrEqual(1);
    const [after] = await adminDb().select().from(wedgetailPosture).where(eq(wedgetailPosture.integrationId, integrationId));
    expect(after!.lastError).toMatch(/refused/);
    expect(after!.ism!.counts.met).toBe(1);
    expect(after!.nextAttemptAt.getTime()).toBe(later.getTime() + 24 * 3600_000);
  });

  it("is tenant-isolated and limits Pull now to managers of the install's customer", async () => {
    expect(await readWedgetailPosture(staff(a), integrationId)).not.toBeNull();
    expect(await readWedgetailPosture(staff(b), integrationId)).toBeNull();
    await expect(refreshWedgetailPosture(staff(b), integrationId)).rejects.toThrow();
    await expect(refreshWedgetailPosture(staff(a, ["integration:read"]), integrationId)).rejects.toThrow();
    await expect(refreshWedgetailPosture(staff(a), randomUUID())).rejects.toThrow(/Not a Wedgetail/);
  });

  it("feeds ISM status into the compliance view and rule coverage into ATT&CK", async () => {
    await syncWedgetailPosture({ force: integrationId, connect: ok });
    const data = await complianceSignals(lead, [a, b], 30);
    expect(data.customers.find((c) => c.tenantId === a)?.wedgetail?.counts).toEqual({ met: 1, partial: 1, not_met: 0, not_applicable: 0 });
    expect(data.customers.find((c) => c.tenantId === a)?.wedgetail?.e8).toEqual({ mfa: { maturity: 1, gap: 2, partlyMet: 0 }, restrict_admin: { maturity: 0, gap: 1, partlyMet: 0 } });
    expect(data.customers.find((c) => c.tenantId === b)?.wedgetail).toBeNull();
    expect(data.wedgetailControls.map((c) => c.id).sort()).toEqual(["ISM-1228", "ISM-1509"]);
    const cells = await attackCoverage(lead, [a]);
    const t1078 = cells.find((c) => c.id === "T1078");
    if (t1078) expect(t1078.externalRules).toBe(1);
    expect((await attackCoverage(lead, [b])).find((c) => c.id === "T1078")?.externalRules ?? 0).toBe(0);
  });
});
