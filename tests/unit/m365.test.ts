import { describe, expect, it } from "vitest";
import { connectorDef, CONNECTORS } from "@/lib/connectors/registry";
import { secretFields } from "@/lib/integrations/form-spec";
import { BEC_DETECTIONS } from "@/lib/detections/bec";
import { parseSigma, runTests } from "@/lib/detections/sigma";
import { GraphError, graphList, graphRequest, type GraphResult, type GraphTransport } from "@/lib/providers/m365/graph";
import { coverageGaps } from "@/lib/providers/m365/licence";
import { actionResult, createM365Provider, ENTRA_REMOTE_PERMISSIONS } from "@/lib/providers/m365/provider";
import { demoGraphTransport } from "@/lib/providers/m365/fixtures";

function scripted(handler: GraphTransport["request"]): GraphTransport {
  return { request: handler };
}

function graph(status: number, body: unknown, headers: Record<string, string> = {}): GraphResult {
  return { status, headers, body };
}

describe("graph throttling and pages", () => {
  it("retries 429 using Retry-After, then returns the success", async () => {
    const sleeps: number[] = [];
    let calls = 0;
    const transport = scripted(async () => {
      calls += 1;
      if (calls < 3) return graph(429, {}, { "Retry-After": "2" });
      return graph(200, { value: [{ id: "ok" }] });
    });
    const res = await graphRequest(transport, "GET", "/auditLogs/signIns", { sleep: async (ms) => { sleeps.push(ms); } });
    expect(res.status).toBe(200);
    expect(calls).toBe(3);
    expect(sleeps).toEqual([2000, 2000]);
  });

  it("gives up after the retry budget", async () => {
    const transport = scripted(async () => graph(429, {}, { "Retry-After": "0" }));
    await expect(graphRequest(transport, "GET", "/auditLogs/signIns", { retries: 1, sleep: async () => undefined })).rejects.toBeInstanceOf(GraphError);
  });

  it("follows nextLink and treats 403 as a coverage denial", async () => {
    const transport = scripted(async (_method, path) => {
      if (path === "/auditLogs/signIns") return graph(200, { value: [{ id: "p1" }], "@odata.nextLink": "/page-2" });
      if (path === "/page-2") return graph(200, { value: [{ id: "p2" }] });
      return graph(403, {});
    });
    const pages = await graphList(transport, "/auditLogs/signIns");
    expect(pages.records.map((r) => r.id)).toEqual(["p1", "p2"]);
    expect(pages.denied).toBe(false);
    const denied = await graphList(transport, "/identityProtection/riskDetections");
    expect(denied.denied).toBe(true);
    expect(denied.records).toEqual([]);
  });
});

describe("licence coverage", () => {
  it("Business Basic has sign-ins and audit, not risk or Intune", () => {
    const gaps = coverageGaps(["O365_BUSINESS_ESSENTIALS"]);
    const byId = Object.fromEntries(gaps.map((g) => [g.id, g.available]));
    expect(byId.signins).toBe(true);
    expect(byId.unified_audit).toBe(true);
    expect(byId.risk_detections).toBe(false);
    expect(byId.intune_devices).toBe(false);
  });

  it("Business Premium adds Intune devices and E5 adds risk detections", () => {
    expect(coverageGaps(["SPB"]).find((g) => g.id === "intune_devices")!.available).toBe(true);
    expect(coverageGaps(["SPB"]).find((g) => g.id === "risk_detections")!.available).toBe(false);
    const e5 = coverageGaps(["SPE_E5"]);
    expect(e5.find((g) => g.id === "intune_devices")!.available).toBe(true);
    expect(e5.find((g) => g.id === "risk_detections")!.available).toBe(true);
  });
});

describe("entra connector", () => {
  it("is available once, with zod config and write-only secrets", () => {
    const matches = CONNECTORS.filter((c) => c.provider === "entra");
    expect(matches).toHaveLength(1);
    const entra = connectorDef("entra")!;
    expect(entra.status).toBe("available");
    expect(entra.remotePermissions).toEqual([...ENTRA_REMOTE_PERMISSIONS]);
    const fields = secretFields("entra");
    expect(fields.map((f) => f.key).sort()).toEqual(["clientId", "clientSecret"]);
    const parsed = entra.config.parse({ azureTenantId: "00000000-0000-4000-8000-000000000000" });
    expect(parsed).not.toHaveProperty("clientSecret");
    expect(parsed).not.toHaveProperty("clientId");
    const inst = entra.create!(parsed, {});
    expect(inst.kind).toBe("events");
  });
});

describe("recorded Graph fixtures", () => {
  const config = { azureTenantId: "00000000-0000-4000-8000-0000000000a1", mode: "fixture" as const, subscribedSkus: ["O365_BUSINESS_ESSENTIALS"] };

  it("normalises the demo tenant and does not re-emit after the checkpoint", async () => {
    const provider = createM365Provider(config, {}, demoGraphTransport());
    const first = await provider.getAlerts({ since: new Date(Date.now() - 7 * 24 * 3600_000) });
    const byId = new Map(first.alerts.map((a) => [a.externalId, a]));
    expect(byId.get("signin:si-legacy")?.attackTechniques).toEqual(["T1078"]);
    expect(byId.get("signin:si-legacy")?.category).toBe("bec");
    expect(byId.get("audit:aud-consent")?.attackTechniques).toEqual(["T1528"]);
    expect(byId.get("audit:aud-role")?.category).toBe("identity");
    expect(byId.get("audit:aud-role")?.attackTechniques).toEqual(["T1098"]);
    expect(byId.get("o365:ex-rule")?.attackTechniques).toEqual(["T1114.003"]);
    expect(byId.get("o365:ex-rule")?.raw.ruleId).toBe("rule-hide-invoices");
    expect(byId.get("o365:ex-forward")?.attackTechniques).toEqual(["T1114.003"]);
    expect(byId.get("o365:ex-mass")?.attackTechniques).toEqual(["T1566.002"]);
    expect(byId.get("travel:si-au:si-us")?.attackTechniques).toEqual(["T1078", "T1114.003"]);
    expect(byId.get("mfa:si-mfa-ok")?.attackTechniques).toEqual(["T1621"]);
    expect(byId.has("o365:ex-benign")).toBe(false);

    const again = createM365Provider(config, {}, demoGraphTransport());
    const second = await again.getAlerts({ since: new Date(Date.now() - 7 * 24 * 3600_000), afterCursor: first.cursor ?? undefined });
    const seen = new Set(first.alerts.map((a) => a.externalId));
    expect(second.alerts.filter((a) => seen.has(a.externalId))).toEqual([]);
  });

  it("lists Intune devices only when the licence includes them", async () => {
    const basic = await createM365Provider(config, {}, demoGraphTransport()).getAssets();
    expect(basic.map((a) => a.kind).sort()).toEqual(["identity", "identity"]);
    const premium = await createM365Provider({ ...config, subscribedSkus: ["SPE_E5"] }, {}, demoGraphTransport()).getAssets();
    expect(premium.some((a) => a.kind === "endpoint" && a.hostname === "WATTLE-LAPTOP")).toBe(true);
  });

  it("shows licence gaps, and a 403 on a licensed signal", async () => {
    const health = await createM365Provider(config, {}, demoGraphTransport()).health();
    const gaps = health.detail.gaps as { id: string; available: boolean; reason: string }[];
    expect(gaps.find((g) => g.id === "risk_detections")!.available).toBe(false);
    expect(gaps.find((g) => g.id === "intune_devices")!.available).toBe(false);

    let riskCalls = 0;
    const transport = scripted(async (method, path) => {
      if (path.includes("riskDetections")) {
        riskCalls += 1;
        return graph(403, {});
      }
      return demoGraphTransport().request(method, path);
    });
    const licensed = createM365Provider({ ...config, subscribedSkus: ["SPE_E5"] }, { clientId: "app", clientSecret: "secret" }, transport);
    await licensed.getAlerts({ since: new Date(Date.now() - 7 * 24 * 3600_000) });
    expect(riskCalls).toBeGreaterThan(0);
    const after = await licensed.health();
    const risk = (after.detail.gaps as { id: string; available: boolean; reason: string }[]).find((g) => g.id === "risk_detections")!;
    expect(risk.available).toBe(false);
    expect(risk.reason).toContain("403");
  });

  it("live mode without secrets fails before any Graph call", async () => {
    const provider = createM365Provider({ ...config, mode: "live", subscribedSkus: [] }, {});
    await expect(provider.getAlerts({})).rejects.toThrow(/clientId/);
  });
});

describe("identity response idempotence", () => {
  const live = { azureTenantId: "tenant", mode: "live" as const, subscribedSkus: [] as string[] };
  const secrets = { clientId: "app", clientSecret: "secret" };

  it("maps Graph status to a result", () => {
    expect(actionResult("revoke_sessions", 204).ok).toBe(true);
    expect(actionResult("remove_inbox_rule", 404).ok).toBe(true);
    expect(actionResult("disable_identity", 404).ok).toBe(false);
    expect(actionResult("revoke_sessions", 400).ok).toBe(false);
  });

  it("does not patch a user who is already disabled", async () => {
    const calls: string[] = [];
    const transport = scripted(async (method, path) => {
      calls.push(`${method} ${path}`);
      if (method === "GET") return graph(200, { accountEnabled: false });
      return graph(204, {});
    });
    const result = await createM365Provider(live, secrets, transport).executeResponseAction({ action: "disable_identity", assetExternalId: "user-finance" });
    expect(result.ok).toBe(true);
    expect(calls.some((c) => c.startsWith("PATCH"))).toBe(false);
  });

  it("disables an enabled user, deletes a rule, and treats an already-removed grant as success", async () => {
    const calls: string[] = [];
    const transport = scripted(async (method, path) => {
      calls.push(`${method} ${path}`);
      if (method === "GET" && path.startsWith("/users/")) return graph(200, { accountEnabled: true });
      if (path.includes("messageRules")) return graph(404, {});
      if (path.includes("oauth2PermissionGrants")) return graph(404, {});
      if (path.includes("authentication/methods") && method === "GET") return graph(200, { value: [] });
      return graph(204, {});
    });
    const provider = createM365Provider(live, secrets, transport);
    expect((await provider.executeResponseAction({ action: "disable_identity", assetExternalId: "user-finance" })).ok).toBe(true);
    expect(calls.some((c) => c.startsWith("PATCH"))).toBe(true);
    const missingRule = await provider.executeResponseAction({ action: "remove_inbox_rule", assetExternalId: "user-finance" });
    expect(missingRule.ok).toBe(false);
    const gone = await provider.executeResponseAction({ action: "remove_inbox_rule", assetExternalId: "user-finance", params: { ruleId: "rule-hide-invoices" } });
    expect(gone.ok).toBe(true);
    const grant = await provider.executeResponseAction({ action: "revoke_oauth_grant", assetExternalId: "user-finance", params: { grantId: "grant-mail" } });
    expect(grant.ok).toBe(true);
    const mfa = await provider.executeResponseAction({ action: "require_mfa", assetExternalId: "user-finance" });
    expect(mfa.ok).toBe(true);
    expect(calls.some((c) => c.includes("authentication/methods") && c.startsWith("DELETE"))).toBe(false);
  });
});

describe("bundled BEC sigma cases", () => {
  it("each detection has a passing positive and a negative case", () => {
    expect(BEC_DETECTIONS.length).toBeGreaterThanOrEqual(7);
    for (const d of BEC_DETECTIONS) {
      expect(d.cases.some((c) => c.expect)).toBe(true);
      expect(d.cases.some((c) => !c.expect)).toBe(true);
      const ran = runTests(parseSigma(d.yaml), d.cases);
      expect(ran.passed, d.yaml.slice(0, 40)).toBe(true);
    }
  });
});
