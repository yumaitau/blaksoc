import { eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, assets, incidents, roleAssignments, roles, tenants, user, vulnerabilities } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { quickSearch } from "@/lib/services/quick-search";

vi.mock("server-only", () => ({}));

const stamp = `palette-${Date.now()}`;
const userId = `${stamp}-analyst`;
const roleKey = `${stamp}-role`;
let a: string, b: string, incRef: number;
let ctx: AccessContext;

beforeAll(async () => {
  await adminDb().insert(user).values({ id: userId, name: "Palette", email: `${userId}@example.invalid`, emailVerified: true });
  await adminDb().insert(roles).values({ key: roleKey, name: "Palette test", scope: "platform", permissions: ["asset:read", "alert:read", "alert:triage", "incident:read", "vuln:read"] });
  await adminDb().insert(roleAssignments).values({ userId, roleKey });
  const rows = await adminDb().insert(tenants).values([
    { name: "Palette A", slug: `${stamp}-a`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
    { name: "Palette B", slug: `${stamp}-b`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
  ]).returning();
  [a, b] = rows.map((r) => r.id) as [string, string];
  ctx = await resolveAccess({ userId, name: "Palette", email: `${userId}@example.invalid`, isBreakGlass: false });
  const [mine, theirs] = await adminDb().insert(assets).values([
    { tenantId: a, name: `${stamp}-ws01`, kind: "endpoint", ips: ["10.9.8.7"] },
    { tenantId: b, name: `${stamp}-ws02`, kind: "endpoint" },
  ]).returning();
  await adminDb().insert(alerts).values([
    { tenantId: a, assetId: mine!.id, source: "test", externalId: `${stamp}-1`, title: `${stamp} mimikatz run`, severity: "high", occurredAt: new Date() },
    { tenantId: b, assetId: theirs!.id, source: "test", externalId: `${stamp}-2`, title: `${stamp} mimikatz other`, severity: "high", occurredAt: new Date() },
  ]);
  const [inc] = await adminDb().insert(incidents).values({ tenantId: a, title: `${stamp} ransomware`, severity: "high" }).returning();
  incRef = inc!.ref;
  await adminDb().insert(vulnerabilities).values({ tenantId: a, assetId: mine!.id, cve: "CVE-2024-3400", packageName: "panos" });
});

afterAll(async () => {
  if (a) await adminDb().delete(tenants).where(inArray(tenants.id, [a, b]));
  await adminDb().delete(user).where(eq(user.id, userId));
  await adminDb().delete(roles).where(eq(roles.key, roleKey));
});

describe("command palette search", () => {
  it("finds assets, alerts and incidents in the workspace only", async () => {
    const hits = await quickSearch(ctx, stamp, [a]);
    expect(hits.map((h) => h.kind).sort()).toEqual(["alert", "asset", "incident"]);
    expect(hits.find((h) => h.kind === "asset")!.title).toBe(`${stamp}-ws01`);
    expect(hits.some((h) => h.title.includes("other"))).toBe(false);
  });

  it("finds an asset by exact IP, an incident by reference and a CVE with its spread", async () => {
    expect((await quickSearch(ctx, "10.9.8.7", [a])).map((h) => h.kind)).toEqual(["asset"]);
    expect((await quickSearch(ctx, `INC-${incRef}`, [a])).find((h) => h.kind === "incident")?.title).toContain("ransomware");
    expect((await quickSearch(ctx, "cve-2024-3400", [a])).find((h) => h.kind === "cve")).toMatchObject({ title: "CVE-2024-3400", detail: "Open on 1 asset", href: "/vulnerabilities?cve=CVE-2024-3400" });
  });

  it("needs the permission in the selected workspace, not just in another tenant", async () => {
    const id = `${stamp}-split`;
    await adminDb().insert(user).values({ id, name: "Split", email: `${id}@example.invalid`, emailVerified: true });
    await adminDb().insert(roles).values([
      { key: `${roleKey}-assets`, name: "Split assets", scope: "tenant", permissions: ["asset:read"] },
      { key: `${roleKey}-vulns`, name: "Split vulns", scope: "tenant", permissions: ["vuln:read"] },
    ]);
    await adminDb().insert(roleAssignments).values([
      { userId: id, roleKey: `${roleKey}-assets`, tenantId: a },
      { userId: id, roleKey: `${roleKey}-vulns`, tenantId: b },
    ]);
    try {
      const split = await resolveAccess({ userId: id, name: "Split", email: `${id}@example.invalid`, isBreakGlass: false });
      expect((await quickSearch(split, "CVE-2024-3400", [a])).some((h) => h.kind === "cve")).toBe(false);
      expect((await quickSearch(split, "CVE-2024-3400", [b])).find((h) => h.kind === "cve")?.detail).toBe("Not open in this workspace");
    } finally {
      await adminDb().delete(user).where(eq(user.id, id));
      await adminDb().delete(roles).where(inArray(roles.key, [`${roleKey}-assets`, `${roleKey}-vulns`]));
    }
  });

  it("treats LIKE wildcards in the query as text", async () => {
    expect(await quickSearch(ctx, "%%", [a])).toEqual([]);
  });
});
