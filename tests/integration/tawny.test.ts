import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, assetSources, assets, auditLog, incidents, incidentTimeline, integrations, playbookRuns, responseActions, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { eventProvider } from "@/lib/connectors/instances";
import { syncAssets } from "@/lib/pipeline/assets";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { advanceRun } from "@/lib/soar/engine";
import { PENDING_TIMEOUT_MS } from "@/lib/soar/pending";
import { decideApproval, executeResponseAction, pollPendingResponseActions, requestFromUser } from "@/lib/soar/response";
import { createIntegration } from "@/lib/services/integrations";
import { runPlaybookManually, savePlaybook } from "@/lib/services/playbooks";

const created: string[] = [];
const TOKEN = "twny_integrationTestToken0123456789abcdef";
const original = globalThis.fetch;

function staff(tenantId: string): AccessContext {
  const permissions: Permission[] = ["integration:manage", "response:request", "response:approve", "playbook:write", "playbook:run", "playbook:read"];
  return {
    principal: { userId: "tawny-lead", name: "Tawny Lead", email: "tawny@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions: new Set(permissions) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "tawny", name: "Banksia Dental", kind: "customer" }],
  };
}

async function setup(mode: "fixture" | "live") {
  const [tenant] = await adminDb().insert(tenants).values({ slug: `tawny-${randomUUID().slice(0, 8)}`, name: "Banksia Dental", kind: "customer" }).returning();
  created.push(tenant!.id);
  const lead = staff(tenant!.id);
  const integrationId = await createIntegration(lead, {
    tenantId: tenant!.id,
    provider: "tawny",
    name: "Tawny",
    config: { apiUrl: "https://tawny.example.com", region: "ap-southeast-2", mode },
    secrets: { apiToken: TOKEN },
  });
  const [row] = await adminDb().select().from(integrations).where(eq(integrations.id, integrationId));
  const [incident] = await adminDb().insert(incidents).values({ tenantId: tenant!.id, title: "Encoded PowerShell", severity: "high" }).returning();
  return { tenant: tenant!, lead, row: row!, incident: incident! };
}

async function assetFor(tenantId: string, row: typeof integrations.$inferSelect) {
  const list = await eventProvider(row).getAssets();
  const ids = await withScope(systemScope(tenantId), (tx) => syncAssets(tx, tenantId, row.id, list));
  return { assetId: ids.get(list[0]!.externalId)!, agentId: list[0]!.externalId };
}

async function actionRow(id: string) {
  return (await adminDb().select().from(responseActions).where(eq(responseActions.id, id)))[0]!;
}

async function timeline(incidentId: string) {
  return (await adminDb().select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, incidentId))).map((row) => row.title);
}

afterEach(() => {
  globalThis.fetch = original;
});

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("tawny response path", () => {
  it("keeps the token out of config, syncs the agent with its platform, and kills a process asynchronously", async () => {
    const { tenant, lead, row, incident } = await setup("fixture");
    expect(JSON.stringify(row.config)).not.toContain(TOKEN);
    expect(row.secretCiphertext).not.toContain(TOKEN);
    expect(row.category).toBe("endpoint");

    const { assetId } = await assetFor(tenant.id, row);
    const [source] = await adminDb().select().from(assetSources).where(eq(assetSources.assetId, assetId));
    expect((source!.raw as { os: { platform: string } }).os.platform).toBe("windows");

    const requested = await requestFromUser(lead, { tenantId: tenant.id, action: "kill_process", target: { assetId, process: "4242" }, reason: "Stop the loader", incidentId: incident.id });
    expect(requested.needsApproval).toBe(true);
    await decideApproval(lead, requested.approvalId!, "APPROVED", "Kill it");

    const sent = await executeResponseAction(tenant.id, requested.action.id);
    expect(sent).toMatchObject({ ok: true, pending: true });
    const inFlight = await actionRow(requested.action.id);
    expect(inFlight.status).toBe("EXECUTING");
    expect(inFlight.integrationId).toBe(row.id);
    expect(inFlight.result).toMatchObject({ pending: true, providerRef: expect.stringContaining("kill_process") });
    expect(await timeline(incident.id)).toContain("Kill process sent to endpoint");

    // A second execute job for the same action does nothing.
    expect(await executeResponseAction(tenant.id, requested.action.id)).toEqual({ skipped: true, status: "EXECUTING" });

    await pollPendingResponseActions();
    const done = await actionRow(requested.action.id);
    expect(done.status).toBe("SUCCEEDED");
    expect(done.result).toEqual({ message: "[fixture] process terminated", providerRef: expect.any(String) });
    expect(done.executedAt).toBeTruthy();
    expect(await timeline(incident.id)).toContain("Kill process succeeded");
    const trail = await adminDb().select().from(auditLog).where(and(eq(auditLog.targetType, "response_action"), eq(auditLog.targetId, requested.action.id)));
    expect(trail.map((r) => r.action)).toEqual(expect.arrayContaining(["response.request", "response.dispatch", "response.execute"]));

    // Settled actions are not polled again.
    await pollPendingResponseActions();
    expect((await timeline(incident.id)).filter((t) => t === "Kill process succeeded")).toHaveLength(1);
  });

  it("reports an isolation the agent cannot do as failed", async () => {
    const { tenant, lead, row, incident } = await setup("fixture");
    const { assetId } = await assetFor(tenant.id, row);
    const requested = await requestFromUser(lead, { tenantId: tenant.id, action: "isolate_endpoint", target: { assetId }, reason: "Contain", incidentId: incident.id });
    await decideApproval(lead, requested.approvalId!, "APPROVED", "Isolate");
    expect(await executeResponseAction(tenant.id, requested.action.id)).toMatchObject({ ok: true, pending: true });
    await pollPendingResponseActions();
    const done = await actionRow(requested.action.id);
    expect(done.status).toBe("FAILED");
    expect((done.result as { message: string }).message).toMatch(/does not support host isolation/);
    expect(await timeline(incident.id)).toContain("Isolate endpoint failed");
  });

  it("refuses a process name before calling Tawny", async () => {
    const { tenant, lead, row } = await setup("fixture");
    const { assetId } = await assetFor(tenant.id, row);
    const requested = await requestFromUser(lead, { tenantId: tenant.id, action: "kill_process", target: { assetId, process: "chrome.exe" }, reason: "Stop it" });
    await decideApproval(lead, requested.approvalId!, "APPROVED", "Kill it");
    expect(await executeResponseAction(tenant.id, requested.action.id)).toMatchObject({ ok: false, message: expect.stringMatching(/numeric process id/) });
    expect((await actionRow(requested.action.id)).status).toBe("FAILED");
  });

  it("sends the blakSOC action id as the idempotency key and fails after the endpoint timeout", async () => {
    const agentId = "7c0e2f4a-1b2c-4d5e-8f90-a1b2c3d4e5f6";
    const posted: unknown[] = [];
    globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/agents")) return Response.json([{ id: agentId, hostname: "chair-3", operating_system: "linux", os_version: "6.8", status: "online", last_heartbeat_at: new Date().toISOString() }]);
      if (init?.method === "POST") {
        posted.push(JSON.parse(String(init.body)));
        return Response.json({ id: "tawny-act-1", agent_id: agentId, action_type: "kill_process", status: "pending" }, { status: 201 });
      }
      return Response.json([{ id: "tawny-act-1", agent_id: agentId, action_type: "kill_process", status: "dispatched" }]);
    }) as typeof fetch;

    const { tenant, lead, row, incident } = await setup("live");
    const { assetId } = await assetFor(tenant.id, row);
    const requested = await requestFromUser(lead, { tenantId: tenant.id, action: "kill_process", target: { assetId, process: "311" }, reason: "Miner", incidentId: incident.id });
    await decideApproval(lead, requested.approvalId!, "APPROVED", "Kill it");
    expect(await executeResponseAction(tenant.id, requested.action.id)).toMatchObject({ ok: true, pending: true });
    expect(posted).toEqual([{ action_type: "kill_process", payload: { pid: 311 }, idempotency_key: requested.action.id }]);
    expect((await actionRow(requested.action.id)).result).toMatchObject({ providerRef: "tawny-act-1" });

    await pollPendingResponseActions(new Date());
    const running = await actionRow(requested.action.id);
    expect(running.status).toBe("EXECUTING");
    expect(running.result).toMatchObject({ providerState: "running", pending: true });

    await pollPendingResponseActions(new Date(Date.now() + PENDING_TIMEOUT_MS + 1000));
    const done = await actionRow(requested.action.id);
    expect(done.status).toBe("FAILED");
    expect((done.result as { message: string }).message).toMatch(/^timed out waiting for endpoint/);
    expect(await timeline(incident.id)).toContain("Kill process failed");
  });

  it("targets the alerting process when a playbook kills it", async () => {
    const { tenant, lead, row } = await setup("fixture");
    const { assetId } = await assetFor(tenant.id, row);
    const [tawnyAlert] = (await eventProvider(row).getAlerts({ afterCursor: "0" })).alerts;
    const [alert] = await adminDb().insert(alerts).values({
      tenantId: tenant.id, source: "tawny", externalId: `${tawnyAlert!.externalId}-${randomUUID()}`, title: tawnyAlert!.title, severity: "high",
      occurredAt: tawnyAlert!.occurredAt, assetId, raw: tawnyAlert!.raw,
    }).returning();
    const playbookId = await savePlaybook(lead, {
      tenantId: tenant.id,
      name: "Kill the loader",
      trigger: { event: "manual", conditions: [] },
      steps: [{ id: "kill", action: "kill_process", name: "Kill the process" }],
    });
    let runId: string;
    try {
      runId = await runPlaybookManually(lead, playbookId, { alertId: alert!.id });
    } catch (err) {
      const [run] = await adminDb().select().from(playbookRuns).where(eq(playbookRuns.alertId, alert!.id));
      if (!run) throw err;
      runId = run.id;
    }
    expect(await advanceRun(tenant.id, runId)).toBe("WAITING_APPROVAL");
    const [action] = await adminDb().select().from(responseActions).where(eq(responseActions.playbookRunId, runId));
    expect(action!.target).toMatchObject({ assetId, process: "4242" });
  });

  it("keeps synchronous providers final and records their provider reference", async () => {
    const { tenant, lead } = await setup("fixture");
    const integrationId = await createIntegration(lead, {
      tenantId: tenant.id, provider: "defender", name: "Defender", config: { tenantDomain: "example.org", mode: "fixture" }, secrets: { clientId: "c", clientSecret: "s" },
    });
    const [asset] = await adminDb().insert(assets).values({ tenantId: tenant.id, kind: "endpoint", name: "reception", hostname: "reception" }).returning();
    await adminDb().insert(assetSources).values({ tenantId: tenant.id, assetId: asset!.id, integrationId, externalId: `device-${randomUUID()}` });
    const requested = await requestFromUser(lead, { tenantId: tenant.id, action: "scan_endpoint", target: { assetId: asset!.id }, reason: "Scan" });
    const result = await executeResponseAction(tenant.id, requested.action.id);
    expect(result).toEqual({ ok: true, message: expect.stringMatching(/^scanned device-/) });
    const done = await actionRow(requested.action.id);
    expect(done.status).toBe("SUCCEEDED");
    expect(done.result).toMatchObject({ message: expect.stringMatching(/^scanned/), providerRef: expect.stringContaining("defender:") });
  });
});
