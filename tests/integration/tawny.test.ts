import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { setEgressTransport } from "@/lib/net/egress";
import { adminDb } from "@/db/client";
import { alerts, assetSources, assets, auditLog, detectionDeployments, incidents, incidentTimeline, integrations, integrationTenantLinks, playbookRuns, responseActions, tenants } from "@/db/schema";
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
import { deployRule, saveRule, setRuleEnabled } from "@/lib/services/detections";

const created: string[] = [];
const TOKEN = "twny_integrationTestToken0123456789abcdef";

function staff(tenantId: string): AccessContext {
  const permissions: Permission[] = ["detection:write", "detection:deploy", "integration:manage", "response:request", "response:approve", "playbook:write", "playbook:run", "playbook:read"];
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
  setEgressTransport();
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
    const tawnyAction = "9f8e7d6c-5b4a-4321-8765-0123456789ab";
    const posted: unknown[] = [];
    const polled: string[] = [];
    setEgressTransport((async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/agents")) return Response.json([{ id: agentId, hostname: "chair-3", operating_system: "linux", os_version: "6.8", status: "online", last_heartbeat_at: new Date().toISOString() }]);
      if (init?.method === "POST") {
        posted.push(JSON.parse(String(init.body)));
        return Response.json({ id: tawnyAction, agent_id: agentId, action_type: "kill_process", status: "pending" }, { status: 201 });
      }
      polled.push(url);
      return Response.json({ id: tawnyAction, agent_id: agentId, action_type: "kill_process", status: "dispatched" });
    }) as typeof fetch);

    const { tenant, lead, row, incident } = await setup("live");
    const { assetId } = await assetFor(tenant.id, row);
    const requested = await requestFromUser(lead, { tenantId: tenant.id, action: "kill_process", target: { assetId, process: "311" }, reason: "Miner", incidentId: incident.id });
    await decideApproval(lead, requested.approvalId!, "APPROVED", "Kill it");
    expect(await executeResponseAction(tenant.id, requested.action.id)).toMatchObject({ ok: true, pending: true });
    expect(posted).toEqual([{ action_type: "kill_process", payload: { pid: 311 }, idempotency_key: requested.action.id }]);
    expect((await actionRow(requested.action.id)).result).toMatchObject({ providerRef: tawnyAction });

    await pollPendingResponseActions(new Date());
    expect(polled).toEqual([`https://tawny.example.com/api/agents/${agentId}/actions/${tawnyAction}`]);
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

  it("deploys a Sigma rule to Tawny and surfaces Tawny's rejection", async () => {
    const yaml = (title: string) => `title: ${title}\nid: ${randomUUID()}\nlevel: high\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: powershell.exe\n  condition: sel\n`;
    const imported: unknown[] = [];
    setEgressTransport((async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/alert-rules")) return Response.json([]);
      const body = JSON.parse(String(init?.body)) as { rule_yaml: string };
      imported.push(body);
      if (body.rule_yaml.includes("Broken")) return Response.json({ title: "Unsupported Sigma field modifier 're'.", status: 400 }, { status: 400 });
      return Response.json({ id: "4d1c1d1e-0000-4000-8000-00000000abcd", name: "PowerShell", format: "sigma" }, { status: 201 });
    }) as typeof fetch);

    const { tenant, lead, row } = await setup("live");
    const good = await saveRule(lead, { tenantId: tenant.id, yaml: yaml("PowerShell") });
    const res = await deployRule(lead, good.id, [tenant.id]);
    expect(res.pushed).toEqual([{ tenantId: tenant.id, integration: "Tawny", message: 'imported to Tawny as "PowerShell"' }]);
    expect(imported).toEqual([{ rule_yaml: expect.stringContaining("title: PowerShell"), is_enabled: true }]);
    const [dep] = await adminDb().select().from(detectionDeployments).where(eq(detectionDeployments.ruleId, good.id));
    expect(dep).toMatchObject({ integrationId: row.id, status: "active", query: "tawny:alert-rule:4d1c1d1e-0000-4000-8000-00000000abcd" });

    const bad = await saveRule(lead, { tenantId: tenant.id, yaml: yaml("Broken") });
    await expect(deployRule(lead, bad.id, [tenant.id])).rejects.toThrow("Tawny rejected the Sigma rule: Unsupported Sigma field modifier 're'.");
    expect(await adminDb().select().from(detectionDeployments).where(eq(detectionDeployments.ruleId, bad.id))).toEqual([]);
  });

  it("keeps the scheduled indexer query for a linked shared SIEM", async () => {
    const { tenant, lead } = await setup("fixture");
    const [shared] = await adminDb().insert(integrations).values({ tenantId: null, category: "siem", provider: "wazuh", name: `Shared ${tenant.slug}`, enabled: true }).returning();
    await adminDb().insert(integrationTenantLinks).values({ integrationId: shared!.id, tenantId: tenant.id, selector: {} });
    const rule = await saveRule(lead, { tenantId: tenant.id, yaml: `title: Shared\nid: ${randomUUID()}\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image|endswith: cmd.exe\n  condition: sel\n` });
    setEgressTransport((() => {
      throw new Error("network");
    }) as typeof fetch);
    const res = await deployRule(lead, rule.id, [tenant.id]);
    expect(res.pushed).toEqual([]);
    const [dep] = await adminDb().select().from(detectionDeployments).where(eq(detectionDeployments.ruleId, rule.id));
    expect(dep).toMatchObject({ integrationId: shared!.id, query: res.query });
    await adminDb().delete(integrations).where(eq(integrations.id, shared!.id));
  });

  it("disables the superseded Tawny rule on redeploy and when the rule is paused", async () => {
    type Rule = { id: string; name: string; format: string; source_definition: string; is_enabled: boolean; operator: string; match_value: string; payload_path: string; severity: string; event_type: string };
    const rules: Rule[] = [];
    const puts: { id: string; body: Record<string, unknown> }[] = [];
    let refuse = false;
    setEgressTransport((async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method === "GET" && url.endsWith("/api/alert-rules")) return Response.json(rules);
      if (method === "POST") {
        const { rule_yaml } = JSON.parse(String(init!.body)) as { rule_yaml: string };
        const rule = { id: randomUUID(), name: `v${rules.length + 1}`, format: "sigma", source_definition: rule_yaml, is_enabled: true, operator: "contains", match_value: "powershell.exe", payload_path: "processes.name", severity: "high", event_type: "process_launch" };
        rules.push(rule);
        return Response.json(rule, { status: 201 });
      }
      const id = url.split("/").at(-1)!;
      if (method === "PUT") {
        if (refuse) return Response.json({ title: "Tawny is read-only today", status: 503 }, { status: 503 });
        const body = JSON.parse(String(init!.body)) as Record<string, unknown>;
        puts.push({ id, body });
        const rule = rules.find((r) => r.id === id)!;
        rule.is_enabled = body.is_enabled as boolean;
        return Response.json(rule);
      }
      return Response.json({ title: "Alert rule has alerts and cannot be deleted. Disable it instead.", status: 409 }, { status: 409 });
    }) as typeof fetch);

    const { tenant, lead } = await setup("live");
    const sigmaId = randomUUID();
    const yaml = (match: string) => `title: PowerShell\nid: ${sigmaId}\nlogsource:\n  product: windows\ndetection:\n  sel:\n    Image|endswith: ${match}\n  condition: sel\n`;
    const saved = await saveRule(lead, { tenantId: tenant.id, yaml: yaml("powershell.exe") });
    await deployRule(lead, saved.id, [tenant.id]);
    expect(rules.map((r) => r.is_enabled)).toEqual([true]);

    await saveRule(lead, { id: saved.id, tenantId: tenant.id, yaml: yaml("pwsh.exe") });
    const res = await deployRule(lead, saved.id, [tenant.id]);
    expect(res.pushed[0]!.message).toMatch(/imported to Tawny as "v2"; disabled Tawny rule "v1"/);
    expect(rules.map((r) => r.is_enabled)).toEqual([false, true]);
    expect(puts[0]).toEqual({ id: rules[0]!.id, body: expect.objectContaining({ is_enabled: false, match_value: "powershell.exe", operator: "contains", payload_path: "processes.name", event_type: "process_launch" }) });

    refuse = true;
    await expect(setRuleEnabled(lead, saved.id, false)).rejects.toThrow(/could not disable rule "v2": Tawny is read-only today; delete failed: Alert rule has alerts/);
    const [still] = await adminDb().select().from(detectionDeployments).where(eq(detectionDeployments.ruleId, saved.id));
    expect(still!.status).toBe("active");

    refuse = false;
    await setRuleEnabled(lead, saved.id, false);
    expect(rules.map((r) => r.is_enabled)).toEqual([false, false]);
    const [paused] = await adminDb().select().from(detectionDeployments).where(eq(detectionDeployments.ruleId, saved.id));
    expect(paused!.status).toBe("paused");
  });
});
