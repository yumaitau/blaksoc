import { randomUUID } from "node:crypto";
import { eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { approvals, assets, dfirCollections, evidence, incidents, integrations, tenantPlans, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { artifactDigest } from "@/lib/dfir/fixture";
import { EntitlementError } from "@/lib/billing/catalogue";
import { AccessDenied } from "@/lib/services/common";
import { custodyExport, releaseScheduledCollection, requestCollection, startHunt } from "@/lib/services/dfir";
import { getIncident } from "@/lib/services/incidents";
import { createIntegration } from "@/lib/services/integrations";
import { decideApproval } from "@/lib/soar/response";

const created: string[] = [];

function staff(tenantId: string, permissions: Permission[], name = "Case Lead"): AccessContext {
  return {
    principal: { userId: `dfir-${name}`, name, email: "dfir@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions: new Set(permissions) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "dfir", name: "Creek Clinic", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `dfir-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Creek Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

async function incidentFor(tenantId: string) {
  const [row] = await adminDb().insert(incidents).values({ tenantId, title: "Clinic laptop", severity: "high" }).returning();
  return row!;
}

async function endpoint(tenantId: string, hostname: string) {
  const [row] = await adminDb().insert(assets).values({ tenantId, kind: "endpoint", name: hostname, hostname }).returning();
  return row!;
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("velociraptor collections", () => {
  it("waits for Plus, approval, and the scheduled upload before evidence is attached", async () => {
    const tenant = await freshTenant();
    const incident = await incidentFor(tenant.id);
    const reader = staff(tenant.id, ["incident:read"], "Reader");
    const analyst = staff(tenant.id, ["incident:read", "incident:write", "response:approve"]);
    const hosts = await Promise.all([1, 2, 3, 4].map((n) => endpoint(tenant.id, `pc-${n}`)));

    await expect(requestCollection(reader, incident.id, { assetIds: [hosts[0]!.id], artifactSets: ["triage"], lowBandwidth: false })).rejects.toBeInstanceOf(AccessDenied);
    await expect(requestCollection(analyst, incident.id, { assetIds: [hosts[0]!.id], artifactSets: ["triage"], lowBandwidth: false })).rejects.toBeInstanceOf(EntitlementError);

    await adminDb().insert(tenantPlans).values({ tenantId: tenant.id, tier: "plus" });
    await expect(requestCollection(analyst, incident.id, { assetIds: [hosts[0]!.id], artifactSets: ["triage"], lowBandwidth: false })).rejects.toThrow(/Velociraptor connector/);

    const integrationId = await createIntegration(staff(tenant.id, ["integration:manage"], "Integrator"), {
      tenantId: tenant.id,
      provider: "velociraptor",
      name: "Velociraptor",
      config: { mode: "live" },
      secrets: {},
    });
    await expect(requestCollection(analyst, incident.id, { assetIds: [hosts[0]!.id], artifactSets: ["triage"], lowBandwidth: false })).rejects.toThrow(/live Velociraptor/);
    await adminDb().update(integrations).set({ config: { mode: "fixture" } }).where(eq(integrations.id, integrationId));

    await expect(requestCollection(analyst, incident.id, {
      assetIds: hosts.map((h) => h.id),
      artifactSets: ["triage"],
      lowBandwidth: true,
    })).rejects.toThrow(/at most 3/);

    const other = await freshTenant();
    const foreign = await endpoint(other.id, "other-pc");
    await expect(requestCollection(analyst, incident.id, { assetIds: [foreign.id], artifactSets: ["triage"], lowBandwidth: false })).rejects.toBeInstanceOf(AccessDenied);

    const requested = await requestCollection(analyst, incident.id, {
      assetIds: [hosts[0]!.id],
      artifactSets: ["triage", "event_logs"],
      lowBandwidth: true,
    });
    expect(requested.status).toBe("pending_approval");
    expect(requested.notBefore.getTime() - Date.now()).toBeGreaterThan(14 * 60_000);
    const [gate] = await adminDb().select().from(approvals).where(eq(approvals.id, requested.approvalId!));
    expect(gate!.kind).toBe("dfir_collection");
    expect(gate!.destructive).toBe(true);

    await decideApproval(analyst, gate!.id, "APPROVED", "Collect after hours");
    const [scheduled] = await adminDb().select().from(dfirCollections).where(eq(dfirCollections.id, requested.id));
    expect(scheduled!.status).toBe("scheduled");
    const early = await adminDb().select().from(evidence).where(eq(evidence.incidentId, incident.id));
    expect(early).toHaveLength(0);

    expect(await releaseScheduledCollection(tenant.id, scheduled!.notBefore)).toBe(1);
    const attached = await adminDb().select().from(evidence).where(eq(evidence.incidentId, incident.id));
    expect(attached).toHaveLength(2);
    const digest = artifactDigest("triage", { id: hosts[0]!.id, hostname: hosts[0]!.hostname, name: hosts[0]!.name });
    expect(attached.some((row) => row.sha256 === digest && row.collectedBy === "Case Lead")).toBe(true);

    const text = await custodyExport(analyst, incident.id);
    expect(text).toContain(`Incident ${incident.ref}`);
    expect(text).toContain(digest);
    expect(text).toContain("by Case Lead");

    const viewed = await getIncident(analyst, incident.id);
    expect(viewed!.evidence).toHaveLength(2);

    const immediate = await requestCollection(analyst, incident.id, {
      assetIds: [hosts[1]!.id],
      artifactSets: ["persistence"],
      lowBandwidth: false,
    });
    await decideApproval(analyst, immediate.approvalId!, "APPROVED", "Collect now");
    const [done] = await adminDb().select().from(dfirCollections).where(eq(dfirCollections.id, immediate.id));
    expect(done!.status).toBe("complete");
    const after = await getIncident(analyst, incident.id);
    expect(after!.evidence.some((row) => row.sha256 === artifactDigest("persistence", { id: hosts[1]!.id, hostname: hosts[1]!.hostname, name: hosts[1]!.name }))).toBe(true);
  });

  it("returns hunt hits only for endpoints inside the caller tenant", async () => {
    const a = await freshTenant();
    const b = await freshTenant();
    for (const tenant of [a, b]) {
      await adminDb().insert(tenantPlans).values({ tenantId: tenant.id, tier: "plus" });
      await createIntegration(staff(tenant.id, ["integration:manage"], "Integrator"), {
        tenantId: tenant.id,
        provider: "velociraptor",
        name: "Velociraptor",
        config: { mode: "fixture" },
        secrets: {},
      });
    }
    const incident = await incidentFor(a.id);
    const own = await endpoint(a.id, "shared-ioc");
    const other = await endpoint(b.id, "shared-ioc");
    const visible = await withScope({ tenantIds: [a.id], platform: false }, (tx) => tx.select({ id: assets.id }).from(assets));
    expect(visible.map((row) => row.id)).toContain(own.id);
    expect(visible.map((row) => row.id)).not.toContain(other.id);

    const hunt = await startHunt(staff(a.id, ["incident:read", "incident:write"]), incident.id, "shared-ioc");
    expect(hunt.matchedAssetIds).toEqual([own.id]);
  });
});
