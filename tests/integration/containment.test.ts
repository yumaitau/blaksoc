import { randomUUID } from "node:crypto";
import { eq, inArray } from "drizzle-orm";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { alerts, assetSources, assets, integrations, playbookRuns, responseActions, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { eventProvider } from "@/lib/connectors/instances";
import { clearFixtureActions } from "@/lib/providers/fixture-action";
import { advanceRun } from "@/lib/soar/engine";
import { decideApproval, executeResponseAction, requestFromUser, requestResponseAction } from "@/lib/soar/response";
import { runPlaybookManually, savePlaybook } from "@/lib/services/playbooks";
import { createIntegration } from "@/lib/services/integrations";

const created: string[] = [];
const TOKEN = "fixture-api-token";

function staff(tenantId: string): AccessContext {
  const permissions: Permission[] = ["integration:manage", "response:request", "response:approve", "playbook:write", "playbook:run", "playbook:read"];
  return {
    principal: { userId: "containment-lead", name: "Containment Lead", email: "contain@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions: new Set(permissions) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "contain", name: "Creek Clinic", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `contain-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Creek Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

beforeEach(() => clearFixtureActions());

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("containment response path", () => {
  it("keeps the API token out of config and rolls a Cloudflare block back", async () => {
    const tenant = await freshTenant();
    const lead = staff(tenant.id);
    const integrationId = await createIntegration(lead, {
      tenantId: tenant.id,
      provider: "cloudflare",
      name: "Cloudflare",
      config: { accountId: "acct-fixture", mode: "fixture" },
      secrets: { apiToken: TOKEN },
    });
    const [row] = await adminDb().select().from(integrations).where(eq(integrations.id, integrationId));
    expect(JSON.stringify(row!.config)).not.toContain(TOKEN);
    expect(row!.secretCiphertext).toBeTruthy();
    expect(row!.secretCiphertext).not.toContain(TOKEN);
    expect(row!.permissions.length).toBeGreaterThan(0);

    const requested = await requestFromUser(lead, {
      tenantId: tenant.id,
      action: "block_ioc",
      target: { observable: "203.0.113.50" },
      reason: "Block the address",
    });
    expect(requested.needsApproval).toBe(true);
    await decideApproval(lead, requested.approvalId!, "APPROVED", "Block it");
    const executed = await executeResponseAction(tenant.id, requested.action.id);
    expect(executed.ok).toBe(true);
    expect(executed.message!.startsWith("already")).toBe(false);
    const again = await eventProvider(row!).executeResponseAction({ action: "block_ioc", assetExternalId: "203.0.113.50", params: { indicator: "203.0.113.50" } });
    expect(again.message.startsWith("already")).toBe(true);

    const release = await withScope({ tenantIds: [tenant.id], platform: false }, (tx) => requestResponseAction(tx, {
      tenantId: tenant.id,
      action: "unblock_ioc",
      target: { observable: "203.0.113.50" },
      reason: "Lift the block",
      requestedBy: lead.principal.userId,
      requestedByKind: "user",
    }));
    expect(release.needsApproval).toBe(false);
    const undone = await executeResponseAction(tenant.id, release.action.id);
    expect(undone).toMatchObject({ ok: true, message: "released 203.0.113.50" });
    const second = await eventProvider(row!).executeResponseAction({ action: "unblock_ioc", assetExternalId: "203.0.113.50", params: { indicator: "203.0.113.50" } });
    expect(second.message).toBe("already released");
  });

  it("isolates a Defender device through approval, then releases it", async () => {
    const tenant = await freshTenant();
    const lead = staff(tenant.id);
    const integrationId = await createIntegration(lead, {
      tenantId: tenant.id,
      provider: "defender",
      name: "Defender",
      config: { tenantDomain: "example.org", mode: "fixture" },
      secrets: { clientId: "fixture-client", clientSecret: "fixture-secret" },
    });
    const [asset] = await adminDb().insert(assets).values({ tenantId: tenant.id, kind: "endpoint", name: "front-desk", hostname: "front-desk" }).returning();
    await adminDb().insert(assetSources).values({ tenantId: tenant.id, assetId: asset!.id, integrationId, externalId: "device-1" });
    const requested = await requestFromUser(lead, {
      tenantId: tenant.id,
      action: "isolate_endpoint",
      target: { assetId: asset!.id },
      reason: "Isolate the machine",
    });
    await decideApproval(lead, requested.approvalId!, "APPROVED", "Isolate");
    const executed = await executeResponseAction(tenant.id, requested.action.id);
    expect(executed).toMatchObject({ ok: true, message: "isolated device-1" });
    const [stored] = await adminDb().select().from(integrations).where(eq(integrations.id, integrationId));
    expect((await eventProvider(stored!).executeResponseAction({ action: "isolate_endpoint", assetExternalId: "device-1" })).message).toMatch(/^already /);

    const release = await withScope({ tenantIds: [tenant.id], platform: false }, (tx) => requestResponseAction(tx, {
      tenantId: tenant.id,
      action: "release_endpoint",
      target: { assetId: asset!.id },
      reason: "Release the machine",
      requestedBy: lead.principal.userId,
      requestedByKind: "user",
    }));
    expect(await executeResponseAction(tenant.id, release.action.id)).toMatchObject({ ok: true, message: "released device-1" });
  });

  it("sends a perimeter block on an endpoint agent to block_ip when that is what the agent supports", async () => {
    const tenant = await freshTenant();
    const lead = staff(tenant.id);
    const integrationId = await createIntegration(lead, {
      tenantId: tenant.id,
      provider: "demo",
      name: "Demo",
      config: { agents: [{ id: "001", name: "pc", group: "g", os: "Windows 11", ip: "10.0.0.5" }] },
      secrets: {},
    });
    const [asset] = await adminDb().insert(assets).values({ tenantId: tenant.id, kind: "endpoint", name: "pc", hostname: "pc" }).returning();
    await adminDb().insert(assetSources).values({ tenantId: tenant.id, assetId: asset!.id, integrationId, externalId: "001" });
    const requested = await requestFromUser(lead, {
      tenantId: tenant.id,
      action: "block_ioc",
      target: { assetId: asset!.id, observable: "203.0.113.50" },
      reason: "Block on the agent",
    });
    await decideApproval(lead, requested.approvalId!, "APPROVED", "Block");
    const executed = await executeResponseAction(tenant.id, requested.action.id);
    expect(executed.ok).toBe(true);
    expect(executed.message).toContain("block_ip");
    expect(executed.message).toContain("001");
    expect(executed.message).not.toContain("block_ioc");
  });

  it("stops a playbook on the perimeter block and records that action", async () => {
    const tenant = await freshTenant();
    const lead = staff(tenant.id);
    await createIntegration(lead, {
      tenantId: tenant.id,
      provider: "fortinet",
      name: "FortiGate",
      config: { host: "https://firewall.example", addressGroup: "blaksoc-block", mode: "fixture" },
      secrets: { apiToken: TOKEN },
    });
    const playbookId = await savePlaybook(lead, {
      tenantId: tenant.id,
      name: "Contain the address",
      trigger: { event: "manual", conditions: [] },
      steps: [
        { id: "block", action: "block_ioc", name: "Block the address" },
        { id: "unblock", action: "unblock_ioc", name: "Remove the block", params: { indicator: "203.0.113.50" } },
        { id: "scan", action: "scan_endpoint", name: "Scan the machine" },
        { id: "isolate", action: "isolate_endpoint", name: "Isolate the machine" },
        { id: "release", action: "release_endpoint", name: "Release the machine" },
      ],
    });
    const [alert] = await adminDb().insert(alerts).values({
      tenantId: tenant.id,
      source: "fortinet",
      externalId: `hit-${randomUUID()}`,
      title: "Perimeter hit",
      severity: "high",
      occurredAt: new Date("2026-01-15T00:00:00.000Z"),
      intel: {
        verdict: "malicious",
        checkedAt: "2026-01-15T00:00:00.000Z",
        matches: [{
          observable: { type: "ipv4", value: "203.0.113.50" },
          openctiId: "fixture",
          entityType: "ipv4-addr",
          verdict: "malicious",
          score: 90,
          confidence: 80,
          source: "fixture",
          markings: [],
          labels: [],
          firstSeen: null,
          lastSeen: null,
          threatActors: [],
          intrusionSets: [],
          malware: [],
          campaigns: [],
          attackPatterns: [],
          relatedIndicators: [],
          sightings: 0,
        }],
      },
    }).returning();

    let runId: string;
    try {
      runId = await runPlaybookManually(lead, playbookId, { alertId: alert!.id });
    } catch (err) {
      const [run] = await adminDb().select().from(playbookRuns).where(eq(playbookRuns.alertId, alert!.id));
      if (!run) throw err;
      runId = run.id;
    }
    expect(await advanceRun(tenant.id, runId)).toBe("WAITING_APPROVAL");
    const actions = await adminDb().select().from(responseActions).where(eq(responseActions.playbookRunId, runId));
    expect(actions.map((row) => row.action)).toEqual(["block_ioc"]);
    expect(actions[0]!.target).toMatchObject({ observable: "203.0.113.50" });
    expect(actions[0]!.status).toBe("AWAITING_APPROVAL");
  });
});
