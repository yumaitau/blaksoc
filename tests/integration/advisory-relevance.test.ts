import { eq, inArray, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { adminDb } from "@/db/client";
import { advisories, alerts, assets, roleAssignments, roles, tenants, user, vulnerabilities } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { socDashboard } from "@/lib/services/dashboard";
import { estateProfile, withRelevance } from "@/lib/services/intel";

vi.mock("server-only", () => ({}));

const stamp = `relevance-${Date.now()}`;
const userId = `${stamp}-analyst`;
const roleKey = `${stamp}-reader`;
let a: string, b: string;
let ctx: AccessContext;

beforeAll(async () => {
  await adminDb().insert(user).values({ id: userId, name: "Intel reader", email: `${userId}@example.invalid`, emailVerified: true });
  await adminDb().insert(roles).values({ key: roleKey, name: "Relevance test", scope: "platform", permissions: ["asset:read", "alert:read", "dashboard:read", "vuln:read"] });
  await adminDb().insert(roleAssignments).values({ userId, roleKey });
  const rows = await adminDb().insert(tenants).values([
    { name: "Relevance A", slug: `${stamp}-a`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
    { name: "Relevance B", slug: `${stamp}-b`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
  ]).returning();
  [a, b] = rows.map((r) => r.id) as [string, string];
  ctx = await resolveAccess({ userId, name: "Intel reader", email: `${userId}@example.invalid`, isBreakGlass: false });
  const made = await adminDb().insert(assets).values([
    { tenantId: a, name: "web01", kind: "server", os: "Ubuntu 22.04.4 LTS", software: [{ name: "openssh-server", version: "1:8.9p1" }, { name: "openssh-client", version: "1:8.9p1" }] },
    { tenantId: a, name: "web02", kind: "server", os: "Ubuntu 22.04.4 LTS", software: [{ name: "openssh-server", version: "1:8.9p1" }] },
    { tenantId: b, name: "fw-mgmt", kind: "server", os: "Microsoft Windows Server 2022", software: [{ name: "Fortinet FortiClient VPN", version: "7.2" }] },
  ]).returning({ id: assets.id, name: assets.name });
  const id = (name: string) => made.find((r) => r.name === name)!.id;
  await adminDb().insert(vulnerabilities).values([
    { tenantId: a, assetId: id("web01"), cve: "CVE-2024-6387", packageName: "openssh-server" },
    { tenantId: a, assetId: id("web02"), cve: "CVE-2024-6387", packageName: "openssh-server" },
    { tenantId: a, assetId: id("web02"), cve: "CVE-2023-0001", packageName: "old", status: "resolved" },
  ]);
  const old = new Date(Date.now() - 45 * 86_400_000);
  await adminDb().insert(alerts).values([
    { tenantId: a, assetId: id("web01"), source: "test", externalId: `${stamp}-1`, title: "Exploit", severity: "high", occurredAt: new Date(), attackTechniques: ["T1190", "T1059.004"] },
    { tenantId: a, assetId: id("web01"), source: "test", externalId: `${stamp}-2`, title: "Noise", severity: "low", occurredAt: new Date(), attackTechniques: ["T1110"], lane: "passive" },
    { tenantId: a, assetId: id("web01"), source: "test", externalId: `${stamp}-3`, title: "Wrong", severity: "low", occurredAt: new Date(), attackTechniques: ["T1078"], status: "FALSE_POSITIVE" },
    { tenantId: a, assetId: id("web01"), source: "test", externalId: `${stamp}-4`, title: "Old", severity: "low", occurredAt: old, attackTechniques: ["T1486"] },
    { tenantId: b, assetId: id("fw-mgmt"), source: "test", externalId: `${stamp}-5`, title: "Other", severity: "high", occurredAt: new Date(), attackTechniques: ["T1003.001"] },
  ]);
});

afterAll(async () => {
  await adminDb().delete(advisories).where(sql`${advisories.externalId} like ${`${stamp}%`}`);
  if (a) await adminDb().delete(tenants).where(inArray(tenants.id, [a, b]));
  await adminDb().delete(user).where(eq(user.id, userId));
  await adminDb().delete(roles).where(eq(roles.key, roleKey));
});

describe("estate profile", () => {
  it("collects open CVEs, installed software, OS and live techniques for the scoped customer only", async () => {
    const p = await estateProfile(ctx, [a]);
    expect(Object.fromEntries(p.cves)).toEqual({ "CVE-2024-6387": 2 });
    expect(Object.fromEntries(p.software)).toEqual({ "openssh-server": 2, "openssh-client": 1 });
    expect(Object.fromEntries(p.os)).toEqual({ "Ubuntu 22.04.4 LTS": 2 });
    // Passive (tuned noise), false-positive and out-of-window alerts do not count.
    expect(Object.fromEntries(p.techniques)).toEqual({ T1190: 1, "T1059.004": 1 });
  });

  it("scores advisories against that estate", async () => {
    const [ssh, forti] = await withRelevance(ctx, [
      { title: "OpenSSH regreSSHion", summary: null, cves: ["CVE-2024-6387"], attackTechniques: ["T1190"] },
      { title: "FortiClient VPN flaw", summary: null, cves: [], attackTechniques: ["T1003.001"] },
    ], [a]);
    expect(ssh!.relevance.cves).toEqual([{ label: "CVE-2024-6387", assets: 2 }]);
    expect(ssh!.relevance.software).toEqual([{ label: "openssh", assets: 2 }]);
    expect(ssh!.relevance.techniques).toEqual([{ label: "T1190", alerts: 1 }]);
    expect(forti!.relevance.score).toBe(0);
  });

  it("leaves techniques out for a caller without alert access", async () => {
    const id = `${stamp}-assets-only`;
    await adminDb().insert(user).values({ id, name: "Assets only", email: `${id}@example.invalid`, emailVerified: true });
    await adminDb().insert(roles).values({ key: `${roleKey}-assets`, name: "Assets only test", scope: "platform", permissions: ["asset:read"] });
    await adminDb().insert(roleAssignments).values({ userId: id, roleKey: `${roleKey}-assets` });
    try {
      const assetsOnly = await resolveAccess({ userId: id, name: "Assets only", email: `${id}@example.invalid`, isBreakGlass: false });
      const p = await estateProfile(assetsOnly, [a]);
      expect(p.cves.size).toBe(1);
      expect(p.techniques.size).toBe(0);
    } finally {
      await adminDb().delete(user).where(eq(user.id, id));
      await adminDb().delete(roles).where(eq(roles.key, `${roleKey}-assets`));
    }
  });

  it("puts an older advisory that touches the estate on the dashboard ahead of newer ones that do not", async () => {
    const day = 86_400_000;
    await adminDb().insert(advisories).values([
      // Newer than everything else in the window, and matching nothing.
      ...Array.from({ length: 80 }, (_, i) => ({ source: "TEST", externalId: `${stamp}-noise-${i}`, title: `${stamp} unrelated appliance ${i}`, url: "https://example.invalid", publishedAt: new Date(Date.now() - i * 60_000) })),
      { source: "TEST", externalId: `${stamp}-ssh`, title: `${stamp} OpenSSH flaw`, url: "https://example.invalid", publishedAt: new Date(Date.now() - 40 * day), cves: ["CVE-2024-6387"] },
      { source: "TEST", externalId: `${stamp}-ancient`, title: `${stamp} OpenSSH ancient flaw`, url: "https://example.invalid", publishedAt: new Date(Date.now() - 400 * day), cves: ["CVE-2024-6387"] },
    ]);
    const d = await socDashboard(ctx, [a]);
    const ids = d.australian.map((x) => x.externalId);
    expect(d.australian).toHaveLength(6);
    expect(ids).toContain(`${stamp}-ssh`);
    // Outside the emerging window, however relevant.
    expect(ids).not.toContain(`${stamp}-ancient`);
    // Nothing irrelevant ranks above it.
    expect(d.australian.slice(0, ids.indexOf(`${stamp}-ssh`)).every((x) => x.relevance.score > 0)).toBe(true);
  });
});
