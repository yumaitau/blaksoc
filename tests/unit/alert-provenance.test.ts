import { describe, expect, it } from "vitest";
import { actorLabel, alertHistory, describeAuditEntry, type AlertAuditRow, type HistoryRefs } from "@/lib/alerts/history";
import { floorSentence, formatDuration, ingestDelay, severityReason, sourceFields, topFactors, wazuhBand } from "@/lib/alerts/provenance";

const wazuhRaw = {
  rule: { id: "5710", level: 10, description: "sshd: attempt to login using a non-existent user", groups: ["syslog", "sshd", "authentication_failed"] },
  decoder: { name: "sshd" },
  location: "/var/log/auth.log",
  agent: { id: "003", name: "web-01", ip: "10.0.0.5" },
  manager: { name: "wazuh-manager" },
};

const value = (fields: { label: string; value: string }[], label: string) => fields.find((f) => f.label === label)?.value;

describe("alert source fields", () => {
  it("reads Wazuh rule, decoder, location, agent and manager", () => {
    const f = sourceFields("wazuh", wazuhRaw);
    expect(value(f, "Rule")).toBe("5710");
    expect(value(f, "Rule level")).toBe("10");
    expect(value(f, "Rule groups")).toBe("syslog, sshd, authentication_failed");
    expect(value(f, "Decoder")).toBe("sshd");
    expect(value(f, "Location")).toBe("/var/log/auth.log");
    expect(value(f, "Agent")).toBe("web-01 (10.0.0.5) · id 003");
    expect(value(f, "Manager")).toBe("wazuh-manager");
  });

  it("skips missing or malformed Wazuh fields instead of throwing", () => {
    expect(sourceFields("wazuh", { rule: "not an object", agent: [1, 2], location: { nested: true } })).toEqual([]);
    expect(sourceFields("wazuh", "a string")).toEqual([]);
    expect(sourceFields("wazuh", null)).toEqual([]);
    expect(value(sourceFields("wazuh", { rule: { groups: ["a", 3, null, { x: 1 }] } }), "Rule groups")).toBe("a, 3");
    expect(value(sourceFields("wazuh", { agent: { name: "db-01" } }), "Agent")).toBe("db-01");
  });

  it("reads syslog endpoints and truncates long lines", () => {
    const f = sourceFields("syslog", { vendor: "fortinet", action: "deny", srcIp: "203.0.113.9", srcPort: 5555, dstIp: "10.0.0.1", proto: "tcp", line: "x".repeat(400) });
    expect(value(f, "Source")).toBe("203.0.113.9:5555");
    expect(value(f, "Destination")).toBe("10.0.0.1");
    expect(value(f, "Line")).toHaveLength(300);
  });

  it("falls back to top-level scalars for other providers", () => {
    expect(sourceFields("google-workspace", { application: "admin", event: "2sv_disable", nested: { a: 1 } })).toEqual([
      { label: "application", value: "admin" },
      { label: "event", value: "2sv_disable" },
    ]);
  });
});

describe("how an alert got its severity", () => {
  it("explains the Wazuh level band", () => {
    expect(wazuhBand("high")).toBe("10–12");
    expect(wazuhBand("critical")).toBe("13 and above");
    expect(severityReason({ source: "wazuh", ruleId: "5710", siemSeverity: 10, severity: "high", raw: wazuhRaw })).toBe(
      "Wazuh rule 5710 fired at level 10; blakSOC maps level 10–12 to high.",
    );
  });

  it("works without raw (withheld from the viewer)", () => {
    expect(severityReason({ source: "wazuh", ruleId: "5710", siemSeverity: null, severity: "high", raw: null })).toBe("Wazuh rule 5710 fired; blakSOC stores it as high.");
    expect(severityReason({ source: "syslog", ruleId: "fortinet:deny", siemSeverity: null, severity: "medium", raw: null })).toContain("rates it medium");
  });

  it("names the correlation rule", () => {
    expect(severityReason({ source: "blaksoc-correlation", ruleId: "mfa_fatigue", siemSeverity: null, severity: "high", raw: null }, "MFA fatigue")).toContain("“MFA fatigue”");
  });

  it("states the alert floor", () => {
    expect(floorSentence("low")).toBe("Stores low and above");
    expect(floorSentence("informational")).toBe("Stores every severity");
  });
});

describe("ingest delay", () => {
  it("formats durations compactly", () => {
    expect(formatDuration(200)).toBe("under a second");
    expect(formatDuration(42_000)).toBe("42 s");
    expect(formatDuration(192_000)).toBe("3 min 12 s");
    expect(formatDuration(180_000)).toBe("3 min");
    expect(formatDuration((2 * 60 + 5) * 60_000)).toBe("2 h 5 min");
    expect(formatDuration((3 * 24 + 4) * 3_600_000)).toBe("3 d 4 h");
  });

  it("flags a source clock that runs ahead", () => {
    const t = new Date("2026-10-08T00:00:00Z");
    expect(ingestDelay(t, new Date(t.getTime() + 90_000))).toBe("stored 1 min 30 s after the event");
    expect(ingestDelay(t, new Date(t.getTime() - 5_000))).toBe("stored 5 s before the event time (the source clock is ahead)");
  });

  it("keeps the largest positive risk factors", () => {
    const f = (key: string, points: number) => ({ key, label: key, points, evidence: "" });
    expect(topFactors([f("a", 5), f("b", 20), f("c", -10), f("d", 12), f("e", 1)]).map((x) => x.key)).toEqual(["b", "d", "a"]);
  });
});

const refs: HistoryRefs = {
  users: new Map([["u2", "Kim Analyst"]]),
  incidents: new Map([["inc1", 42]]),
  responseActions: new Map([["ra1", "isolate_endpoint"]]),
};

const row = (action: string, detail: unknown, extra: Partial<AlertAuditRow> = {}): AlertAuditRow => ({
  id: 1, at: new Date("2026-10-08T01:00:00Z"), action, actorId: "u1", actorKind: "user", actorName: "Sam Lead", targetType: "alert", targetId: "a1", detail, ...extra,
});

describe("audit entry sentences", () => {
  it("describes status and assignment changes", () => {
    expect(describeAuditEntry(row("alert.update", { from: "NEW", status: "TRIAGING" }), refs).text).toBe("Changed status from new to triaging");
    expect(describeAuditEntry(row("alert.update", { from: "NEW", status: "FALSE_POSITIVE", assigneeId: "u1" }), refs).text).toBe("Changed status from new to false positive and took the alert");
    expect(describeAuditEntry(row("alert.update", { from: "TRIAGING", assigneeId: "u2" }), refs).text).toBe("Assigned it to Kim Analyst");
    expect(describeAuditEntry(row("alert.update", { from: "TRIAGING", assigneeId: null }), refs).text).toBe("Unassigned the alert");
    expect(describeAuditEntry(row("alert.update", null), refs).text).toBe("Updated the alert");
  });

  it("describes correlation, incident and response entries", () => {
    expect(describeAuditEntry(row("correlation.finding", { ruleId: "unknown_rule", eventIds: ["x", "y"] }), refs).text).toBe("Raised by correlation rule “unknown_rule” from 2 alerts");
    expect(describeAuditEntry(row("incident.create", { alertIds: ["a1", "a2"] }, { targetType: "incident", targetId: "inc1" }), refs)).toEqual({ text: "Opened incident INC-42 with 1 other alert", href: "/soc/incidents/inc1" });
    expect(describeAuditEntry(row("incident.ungroup", { alertIds: ["a1"], closed: true }, { targetType: "incident", targetId: "nope" }), refs).text).toBe("Removed from an incident; the incident was closed");
    expect(describeAuditEntry(row("response.request", { action: "isolate_endpoint", needsApproval: true }, { targetType: "response_action", targetId: "ra1" }), refs).text).toBe("Requested “Isolate endpoint” (awaiting approval)");
    expect(describeAuditEntry(row("response.execute", { ok: false, message: "agent offline" }, { targetType: "response_action", targetId: "ra1" }), refs).text).toBe("“Isolate endpoint” failed: agent offline");
    expect(describeAuditEntry(row("approval.approved", {}, { targetType: "response_action", targetId: "ra1" }), refs).text).toBe("Approved “Isolate endpoint”");
    expect(describeAuditEntry(row("playbook.start", { playbook: "Contain ransomware", event: "alert.created" }), refs).text).toBe("Playbook “Contain ransomware” started when the alert was created");
  });

  it("falls back to the raw action", () => {
    expect(describeAuditEntry(row("alert.something_new", { x: 1 }), refs).text).toBe("alert.something_new");
  });

  it("labels actors", () => {
    expect(actorLabel("system", null)).toBe("system");
    expect(actorLabel("user", "Sam Lead")).toBe("Sam Lead");
    expect(actorLabel("service", null)).toBe("API client");
    expect(actorLabel("ai", "Sam Lead")).toBe("AI analyst (for Sam Lead)");
  });

  it("starts with the ingest and orders entries by time", () => {
    const later = row("alert.update", { from: "NEW", status: "RESOLVED" }, { id: 9, at: new Date("2026-10-08T03:00:00Z") });
    const earlier = row("correlation.finding", { ruleId: "r" }, { id: 7, at: new Date("2026-10-08T02:00:00Z"), actorKind: "system", actorId: null, actorName: null });
    const h = alertHistory({ ingestedAt: new Date("2026-10-08T00:00:00Z"), severity: "high", source: "wazuh", integrationName: null }, [later, earlier], refs);
    expect(h.map((e) => e.key)).toEqual(["ingest", "7", "9"]);
    expect(h[0]).toMatchObject({ actor: "system", text: "Stored as a high alert from Wazuh" });
    expect(h[1]!.actor).toBe("system");
  });

  it("marks Hermes' entries, not the analyst who undid them", () => {
    const hermes = { actorKind: "service", actorId: "svc1", actorName: "hermes-prod" };
    const closed = row("tuning.close", { reason: "Scanner noise", affected: 4 }, { id: 3, targetType: "tuning_action", targetId: "ta1", ...hermes });
    const undone = row("tuning.undo", { kind: "close", restored: 4 }, { id: 4, targetType: "tuning_action", targetId: "ta1" });
    const h = alertHistory({ ingestedAt: new Date("2026-10-08T00:00:00Z"), severity: "low", source: "wazuh", integrationName: null }, [closed, undone], refs);
    expect(h[1]).toMatchObject({ hermes: true, actor: "Hermes (AI)", text: "Closed it as a false positive (“Scanner noise”)" });
    expect(h[2]!.hermes).toBeUndefined();
    expect(h[2]!.actor).toBe("Sam Lead");
    expect(h[0]!.hermes).toBeUndefined();
  });
});
