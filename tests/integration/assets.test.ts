import { eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, assets, assetSources, integrations, roleAssignments, roles, tenants, user } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { assetSummary, listAssets, type AgentFilter } from "@/lib/services/assets";
import { portalOverview } from "@/lib/services/portal";

vi.mock("server-only", () => ({}));

const stamp = `assets-${Date.now()}`;
const userId = `${stamp}-analyst`;
const roleKey = `${stamp}-reader`;
let a: string, b: string;
let ctx: AccessContext;

beforeAll(async () => {
  await adminDb().insert(user).values({ id: userId, name: "Asset reader", email: `${userId}@example.invalid`, emailVerified: true });
  await adminDb().insert(roles).values({ key: roleKey, name: "Asset reader test", scope: "platform", permissions: ["asset:read", "portal:read"] });
  await adminDb().insert(roleAssignments).values({ userId, roleKey });
  const rows = await adminDb().insert(tenants).values([
    { name: "Asset customer A", slug: `${stamp}-a`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
    { name: "Asset customer B", slug: `${stamp}-b`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
  ]).returning();
  [a, b] = rows.map((r) => r.id) as [string, string];
  ctx = await resolveAccess({ userId, name: "Asset reader", email: `${userId}@example.invalid`, isBreakGlass: false });
  const made = await adminDb().insert(assets).values([
    { tenantId: a, name: "quiet-online", kind: "endpoint", agentStatus: "active" },
    { tenantId: a, name: "alerting-online", kind: "endpoint", agentStatus: "active" },
    { tenantId: a, name: "gone-dark", kind: "endpoint", agentStatus: "disconnected" },
    { tenantId: a, name: "no-agent", kind: "server", agentStatus: null },
    { tenantId: a, name: "disabled-user", kind: "identity", agentStatus: "disabled" },
    { tenantId: a, name: "alerting-user", kind: "identity", agentStatus: "active" },
    { tenantId: a, name: "intune-failing", kind: "endpoint", agentStatus: "active" },
    { tenantId: a, name: "intune-grace", kind: "endpoint", agentStatus: "active" },
    { tenantId: b, name: "other-customer", kind: "endpoint", agentStatus: "disconnected" },
  ]).returning({ id: assets.id, name: assets.name });
  const id = (name: string) => made.find((r) => r.name === name)!.id;
  await adminDb().insert(alerts).values([
    { tenantId: a, assetId: id("alerting-online"), source: "test", externalId: `${stamp}-1`, title: "Open", severity: "high", occurredAt: new Date() },
    { tenantId: a, assetId: id("alerting-user"), source: "test", externalId: `${stamp}-2`, title: "Open", severity: "medium", occurredAt: new Date() },
    { tenantId: a, assetId: id("quiet-online"), source: "test", externalId: `${stamp}-3`, title: "Closed", severity: "high", status: "RESOLVED", occurredAt: new Date() },
  ]);
  const [m365] = await adminDb().insert(integrations).values({ tenantId: a, category: "identity", provider: "m365", name: "M365" }).returning();
  await adminDb().insert(assetSources).values([
    { tenantId: a, assetId: id("intune-failing"), integrationId: m365!.id, externalId: "intune-1", raw: { complianceState: "noncompliant" } },
    { tenantId: a, assetId: id("intune-grace"), integrationId: m365!.id, externalId: "intune-2", raw: { complianceState: "inGracePeriod" } },
    { tenantId: a, assetId: id("quiet-online"), integrationId: m365!.id, externalId: "intune-3", raw: { complianceState: "compliant" } },
  ]);
});

afterAll(async () => {
  if (a) await adminDb().delete(tenants).where(inArray(tenants.id, [a, b]));
  await adminDb().delete(user).where(eq(user.id, userId));
  await adminDb().delete(roles).where(eq(roles.key, roleKey));
});

describe("asset inventory agent coverage", () => {
  it("counts endpoint agents and everything needing attention for the scoped customer", async () => {
    expect(await assetSummary(ctx, [a])).toEqual({ endpoints: 6, online: 4, offline: 1, none: 1, noncompliant: 1, attention: 5 });
  });

  it("filters the list by agent state", async () => {
    const names = async (agent: AgentFilter) => (await listAssets(ctx, { tenantIds: [a], agent })).map((r) => r.name).sort();
    expect(await names("online")).toEqual(["alerting-online", "intune-failing", "intune-grace", "quiet-online"]);
    expect(await names("offline")).toEqual(["gone-dark"]);
    expect(await names("none")).toEqual(["no-agent"]);
    expect(await names("noncompliant")).toEqual(["intune-failing"]);
    expect(await names("attention")).toEqual(["alerting-online", "alerting-user", "gone-dark", "intune-failing", "no-agent"]);
    expect((await listAssets(ctx, { tenantIds: [a] })).filter((r) => r.nonCompliant).map((r) => r.name)).toEqual(["intune-failing"]);
  });

  it("tells the customer portal about non-compliant devices", async () => {
    const o = await portalOverview(ctx, a);
    expect(o.endpoints).toEqual({ total: 6, online: 4, offline: 1, unmanaged: 1, noncompliant: 1 });
    expect(o.recommendations).toContainEqual(expect.objectContaining({ priority: "high", href: "/assets?agent=noncompliant" }));
  });
});
