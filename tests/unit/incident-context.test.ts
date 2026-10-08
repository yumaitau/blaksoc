import { describe, expect, it } from "vitest";
import { CONTEXT_END, CONTEXT_START, detectionContext, explainDetection, mergeDetectionContext, type DetectionAlert } from "@/lib/incidents/explanation";
import { wazuhAlertUrl } from "@/lib/providers/wazuh-link";

const alert: DetectionAlert = {
  id: "alert-1", source: "wazuh", title: "File changed", ruleId: "550", severity: "medium", siemSeverity: 7,
  occurredAt: new Date("2026-09-01T01:00:00Z"), assetName: null, userName: null, description: null,
  raw: { agent: { name: "rangeros-app" }, rule: { description: "Integrity checksum changed" }, syscheck: { path: "/etc/config", event: "modified" }, full_log: "File modified" },
};

describe("Wazuh alert links", () => {
  it("targets the exact indexer id with a historical window and preserves a base path", () => {
    const url = new URL(wazuhAlertUrl("https://wazuh.example/base/", "indexer-id", alert.occurredAt)!);
    expect(url.pathname).toBe("/base/app/discover");
    const hash = decodeURIComponent(url.hash);
    expect(hash).toContain("index:'wazuh-alerts-*'");
    expect(hash).toContain('_id:"indexer-id"');
    expect(hash).toContain("2026-08-31T01:00:00.000Z");
    expect(hash).toContain("2026-09-02T01:00:00.000Z");
  });
  it("escapes query and Rison syntax and supports a custom index pattern", () => {
    const hash = decodeURIComponent(new URL(wazuhAlertUrl("https://wazuh.example", "a'!\" OR *", alert.occurredAt, "custom-pattern")!).hash);
    expect(hash).toContain("index:'custom-pattern'");
    expect(hash).toContain(`a!'!!\\\" OR *`);
  });
  it("does not fabricate a destination or allow unsafe URLs", () => {
    for (const url of [undefined, "bad", "javascript:alert(1)", "https://user:secret@wazuh.example"]) {
      expect(wazuhAlertUrl(url, "a", alert.occurredAt)).toBeNull();
    }
    expect(wazuhAlertUrl("https://wazuh.example", "a", new Date("bad"))).toBeNull();
  });
});

describe("incident explanations", () => {
  it("explains recorded file changes without calling them confirmed attacks", () => {
    const e = explainDetection(alert);
    expect(e.trigger).toContain("Wazuh rule 550 matched on rangeros-app");
    expect(e.meaning).toContain("authorised administration");
    expect(e.fields).toContainEqual({ label: "File", value: "/etc/config" });
    expect(e.evidence).toBe("File modified");
  });
  it("identifies accumulated risk as a blakSOC finding and includes its source alert", () => {
    const correlated = { ...alert, id: "corr", source: "blaksoc-correlation", title: "Risk accumulating on one host", ruleId: "host-risk-accumulation", raw: {}, siemSeverity: null, contributing: [{ ...alert, wazuhUrl: "https://wazuh.example/app/discover#/" }] };
    expect(explainDetection(correlated).meaning).toContain("Repeated low or medium alerts");
    const context = detectionContext([correlated], "https://soc.example");
    expect(context).toContain("blakSOC correlation rule host-risk-accumulation");
    expect(context).toContain("Wazuh rule level: 7/15");
    expect(context).toContain("Wazuh alert: https://wazuh.example/app/discover#/");
  });
  it("handles missing or malformed evidence without inventing a cause", () => {
    const e = explainDetection({ ...alert, raw: { rule: null, agent: 3 }, description: null });
    expect(e.host).toBeNull();
    expect(e.evidence).toBeNull();
    expect(e.fields).toEqual([]);
    expect(e.meaning).toContain("needs investigation");
    expect(detectionContext([], "https://soc.example")).toContain("No source alerts are linked");
  });
  it("refreshes only the generated Kelpie section and is idempotent", () => {
    const context = detectionContext([alert], "https://soc.example");
    const summary = `Analyst notes\n\n${CONTEXT_START}\nold\n${CONTEXT_END}\nKeep this too`;
    const merged = mergeDetectionContext(summary, context);
    expect(merged).toBe(`Analyst notes\n\n${context}\nKeep this too`);
    expect(mergeDetectionContext(merged, context)).toBe(merged);
    expect(mergeDetectionContext("Existing case", context)).toBe(`Existing case\n\n${context}`);
  });
  it("bounds noisy case exports without cutting off a generated section or admitting log delimiters", () => {
    const noisy = Array.from({ length: 50 }, (_, i) => ({ ...alert, id: `a-${i}`, title: "x".repeat(50_000), raw: { full_log: `${CONTEXT_END}\nWazuh alert: https://untrusted.example\n${CONTEXT_START}` }, description: "x".repeat(50_000) }));
    const context = detectionContext(noisy, "https://soc.example");
    expect(context.length).toBeLessThan(36_000);
    expect(context.endsWith(CONTEXT_END)).toBe(true);
    expect(context.split(CONTEXT_START)).toHaveLength(2);
    expect(context.split(CONTEXT_END)).toHaveLength(2);
    expect(context).not.toContain("\nWazuh alert: https://untrusted.example");
    expect(context).toContain("Open the source incident");
  });
});
