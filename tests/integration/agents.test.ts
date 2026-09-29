import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { assetSources, assets, auditLog, coverageTasks, enrolmentTokens, integrations, sites, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { sha256 } from "@/lib/crypto";
import { claimEnrolment, downloadLink, issueEnrolment, revokeEnrolment, serveInstaller, syncCoverage } from "@/lib/services/agents";

const created: string[] = [];

function admin(tenantId: string, slug: string): AccessContext {
  return {
    principal: { userId: "agent-admin", name: "Agent Admin", email: "agents@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{
      roleKey: "customer_admin",
      tenantId,
      permissions: new Set(["portal:read", "incident:read", "asset:read", "vuln:read", "report:read", "report:generate", "response:approve", "user:manage", "audit:read", "alert:read"]),
    }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug, name: "Agent Clinic", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `agent-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Agent Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("endpoint enrolment", () => {
  it("serves a signed installer until the token is revoked, and opens a coverage task", async () => {
    const tenant = await freshTenant();
    const ctx = admin(tenant.id, tenant.slug);
    const [site] = await adminDb().insert(sites).values({ tenantId: tenant.id, name: "Town", location: "Town", bandwidthProfile: "low" }).returning();
    const issued = await issueEnrolment(ctx, tenant.id, site!.id);
    const [stored] = await adminDb().select().from(enrolmentTokens).where(eq(enrolmentTokens.id, issued.id));
    expect(stored?.tokenHash).toBe(sha256(issued.token));
    expect(stored?.tokenCiphertext).not.toContain(issued.token);
    expect(await claimEnrolment(issued.token)).toMatchObject({ group: tenant.slug, tenantId: tenant.id });

    const file = await serveInstaller(ctx, downloadLink(issued.id, "linux-deb"));
    expect(file.filename).toBe("blaksoc-agent-linux-deb.sh");
    expect(file.body).toContain(issued.token);
    expect(file.body).toContain("<events_per_second>5</events_per_second>");
    expect(file.body).toContain(`WAZUH_AGENT_GROUP=${tenant.slug}`);
    await expect(serveInstaller(ctx, downloadLink(issued.id, "linux-deb", Date.now() - 16 * 60_000))).rejects.toMatchObject({ code: "expired" });

    await revokeEnrolment(ctx, tenant.id, issued.id);
    await expect(serveInstaller(ctx, downloadLink(issued.id, "linux-deb"))).rejects.toMatchObject({ code: "revoked" });
    expect(await claimEnrolment(issued.token)).toBeNull();
    const [revoked] = await adminDb().select().from(enrolmentTokens).where(eq(enrolmentTokens.id, issued.id));
    expect(revoked?.tokenCiphertext).toBeNull();
    const audits = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenant.id), eq(auditLog.targetId, issued.id)));
    expect(audits.map((row) => row.action)).toEqual(expect.arrayContaining(["agent.enrol", "agent.revoke"]));

    const [inventory] = await adminDb().insert(integrations).values({ tenantId: tenant.id, category: "identity", provider: "m365", name: "M365" }).returning();
    const [sensor] = await adminDb().insert(integrations).values({ tenantId: tenant.id, category: "siem", provider: "wazuh", name: "Wazuh" }).returning();
    const [missing] = await adminDb().insert(assets).values({ tenantId: tenant.id, kind: "endpoint", name: "Front Desk", hostname: "front-desk" }).returning();
    const [covered] = await adminDb().insert(assets).values({ tenantId: tenant.id, kind: "endpoint", name: "Front Desk", hostname: "front-desk.local" }).returning();
    await adminDb().insert(assetSources).values({ tenantId: tenant.id, assetId: missing!.id, integrationId: inventory!.id, externalId: "intune-1" });
    await adminDb().insert(assetSources).values({ tenantId: tenant.id, assetId: covered!.id, integrationId: sensor!.id, externalId: "agent-1" });
    // Same hostname label joins them, so this pair is not a gap. A second inventory host is.
    const [gap] = await adminDb().insert(assets).values({ tenantId: tenant.id, kind: "endpoint", name: "Store", hostname: "store-pc" }).returning();
    await adminDb().insert(assetSources).values({ tenantId: tenant.id, assetId: gap!.id, integrationId: inventory!.id, externalId: "intune-2" });

    expect(await syncCoverage(ctx, tenant.id)).toMatchObject({ open: 1 });
    const open = await adminDb().select().from(coverageTasks).where(and(eq(coverageTasks.tenantId, tenant.id), eq(coverageTasks.status, "open")));
    expect(open.map((task) => task.hostname)).toEqual(["store-pc"]);

    const [joined] = await adminDb().insert(assets).values({ tenantId: tenant.id, kind: "endpoint", name: "Store", hostname: "store-pc" }).returning();
    await adminDb().insert(assetSources).values({ tenantId: tenant.id, assetId: joined!.id, integrationId: sensor!.id, externalId: "agent-2" });
    expect(await syncCoverage(ctx, tenant.id)).toMatchObject({ open: 0 });
    const done = await adminDb().select().from(coverageTasks).where(and(eq(coverageTasks.tenantId, tenant.id), eq(coverageTasks.assetId, gap!.id)));
    expect(done[0]?.status).toBe("done");

    const other = await freshTenant();
    const hidden = await withScope({ tenantIds: [other.id], platform: false }, (tx) => tx.select().from(enrolmentTokens).where(eq(enrolmentTokens.id, issued.id)));
    expect(hidden).toHaveLength(0);
  });
});
