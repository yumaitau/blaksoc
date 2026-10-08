import { describe, expect, it } from "vitest";
import { auditCsv, csvCell } from "@/lib/audit/csv";
import { auditNameIds, auditTargetHref, describeAuditEntry, isHermesActor, isSecretKey, redactAuditDetail } from "@/lib/audit/describe";
import { auditQuery, parseAuditFilters } from "@/lib/audit/filters";

const ALERT = "6f0c3a52-8e1d-4b8a-9a43-1f2d3c4b5a69";
const USER = "u_7Hq2kd9";

describe("describeAuditEntry", () => {
  it("words an alert status change and assignment, linking the alert", () => {
    const d = describeAuditEntry(
      { action: "alert.update", actorKind: "user", targetType: "alert", targetId: ALERT, detail: { from: "NEW", status: "FALSE_POSITIVE", assigneeId: USER } },
      { [USER]: "Jane Analyst" },
    );
    expect(d.summary).toBe("Changed alert status from new to false positive and assigned the alert to Jane Analyst");
    expect(d.targetHref).toBe(`/soc/alerts/${ALERT}`);
  });

  it("says when an alert is unassigned", () => {
    expect(describeAuditEntry({ action: "alert.update", detail: { from: "NEW", assigneeId: null } }).summary).toBe("Unassigned the alert");
  });

  it("names the role and person on rbac changes", () => {
    const names = { [USER]: "Sam Admin" };
    expect(describeAuditEntry({ action: "rbac.assign", targetType: "user", targetId: USER, detail: { userId: USER, roleKey: "soc_l2", tenantId: null } }, names).summary).toBe(
      "Granted the soc l2 role to Sam Admin (platform-wide)",
    );
    expect(describeAuditEntry({ action: "rbac.revoke", targetType: "user", targetId: USER, detail: { roleKey: "auditor" } }, names).summary).toBe("Revoked the auditor role from Sam Admin");
    expect(describeAuditEntry({ action: "rbac.revoke", targetType: "user", targetId: USER, detail: { roleKey: "auditor" } }).summary).toBe("Revoked the auditor role from user u_7Hq2kd");
  });

  it("covers integrations, incidents, responses and retention", () => {
    expect(describeAuditEntry({ action: "integration.create", targetType: "integration", targetId: "i1", detail: { provider: "wazuh", name: "Prod manager", secretKeys: ["password"] } })).toEqual({
      summary: "Added the wazuh integration “Prod manager”",
      targetHref: "/integrations/i1",
    });
    expect(describeAuditEntry({ action: "integration.update", detail: { fields: ["name", "secrets"] } }).summary).toBe("Updated the integration's name and credentials");
    expect(describeAuditEntry({ action: "integration.test", detail: { ok: false } }).summary).toBe("Tested the integration connection: failed");
    expect(describeAuditEntry({ action: "incident.create", targetType: "incident", targetId: "inc-1", detail: { alertIds: ["a", "b"] } })).toEqual({
      summary: "Opened an incident from 2 alerts",
      targetHref: "/soc/incidents/inc-1",
    });
    expect(describeAuditEntry({ action: "incident.update", detail: { patch: { status: "CONTAINED", ownerId: null, rootCause: "x" } } }).summary).toBe(
      "Set the incident status to contained, unassigned it and updated root cause",
    );
    expect(describeAuditEntry({ action: "response.request", detail: { action: "isolate_endpoint", needsApproval: true } }).summary).toBe("Requested response: Isolate endpoint (needs approval)");
    expect(describeAuditEntry({ action: "response.execute", detail: { ok: false, message: "agent offline" } }).summary).toBe("Response action failed: agent offline");
    expect(describeAuditEntry({ action: "retention.purge_alerts", targetType: "tenant", targetId: "t1", detail: { severity: "low", deleted: 12, retentionDays: 90 } })).toEqual({
      summary: "Purged 12 low alerts older than 90 days",
      targetHref: "/soc/alerts?tenant=t1",
    });
    expect(describeAuditEntry({ action: "approval.approved", targetType: "response_action", targetId: "r1" }).summary).toBe("Approved a response action");
  });

  it("lists changed customer settings with before → after for simple values", () => {
    const d = describeAuditEntry({ action: "tenant.settings", detail: { before: { autoContainment: false, sharing: { a: 1 } }, after: { autoContainment: true, sharing: { a: 2 } } } });
    expect(d.summary).toBe("Changed customer settings: auto containment off → on and sharing");
  });

  it("uses prefixes for families it has no exact wording for", () => {
    expect(describeAuditEntry({ action: "auth.passkey.add" }).summary).toBe("Added a passkey");
    expect(describeAuditEntry({ action: "auth.sign_in" }).summary).toBe("Authentication: sign in");
  });

  it("falls back to the raw key for unknown actions and odd details", () => {
    expect(describeAuditEntry({ action: "widget.frobnicate", targetType: "widget", targetId: "w1" })).toEqual({ summary: "widget.frobnicate" });
    expect(describeAuditEntry({ action: "constructor" }).summary).toBe("constructor");
    expect(describeAuditEntry({ action: "alert.update", detail: "not an object" }).summary).toBe("Updated the alert");
  });
});

describe("audit targets and names", () => {
  it("links only targets that have a page", () => {
    expect(auditTargetHref("playbook_run", "r1")).toBe("/soar/runs/r1");
    expect(auditTargetHref("user", USER)).toBe(`/admin/audit?targetType=user&targetId=${USER}`);
    expect(auditTargetHref("response_action", "r1")).toBeUndefined();
    expect(auditTargetHref("alert", "../../x")).toBe("/soc/alerts/..%2F..%2Fx");
  });

  it("collects the user ids a summary refers to", () => {
    expect(auditNameIds({ action: "incident.update", targetType: "user", targetId: "u1", detail: { assigneeId: "u2", patch: { ownerId: "u3" } } })).toEqual(["u2", "u3", "u1"]);
  });
});

describe("redactAuditDetail", () => {
  it("redacts secret-looking keys at any depth and keeps the rest", () => {
    const out = redactAuditDetail({
      name: "Prod",
      password: "hunter2",
      clientSecret: "s3cr3t",
      config: { api_key: "k", accessToken: "t", secretCiphertext: "c", roleKey: "auditor", dedupeKey: "d" },
      list: [{ refreshToken: "r", ok: true }],
      key: "bare",
    });
    expect(out).toEqual({
      name: "Prod",
      password: "[redacted]",
      clientSecret: "[redacted]",
      config: { api_key: "[redacted]", accessToken: "[redacted]", secretCiphertext: "[redacted]", roleKey: "auditor", dedupeKey: "d" },
      list: [{ refreshToken: "[redacted]", ok: true }],
      key: "[redacted]",
    });
    expect(JSON.stringify(out)).not.toMatch(/hunter2|s3cr3t/);
  });

  it("recognises secret names however they are cased", () => {
    for (const k of ["PASSWORD", "db_password", "apiKey", "privateKey", "x-auth-token", "sessionCookie"]) expect(isSecretKey(k), k).toBe(true);
    for (const k of ["roleKey", "groupingKey", "status", "keyboard", "monkey"]) expect(isSecretKey(k), k).toBe(false);
  });

  it("leaves primitives and null alone", () => {
    expect(redactAuditDetail(null)).toBeNull();
    expect(redactAuditDetail("password")).toBe("password");
  });
});

describe("audit CSV", () => {
  it("neutralises spreadsheet formulas and escapes quotes", () => {
    expect(csvCell("=HYPERLINK(\"x\")")).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvCell("plain")).toBe(`"plain"`);
    expect(csvCell(null)).toBe(`""`);
  });

  it("writes the summary and redacted detail for each row", () => {
    const csv = auditCsv([
      {
        entry: { id: 7, at: new Date("2026-01-02T03:04:05Z"), actorId: USER, actorKind: "user", tenantId: null, action: "integration.create", targetType: "integration", targetId: "i1", ip: "203.0.113.9", hash: "abc", detail: { name: "X", token: "leak" } },
        actorName: "Jane",
        actorEmail: "jane@example.com",
        tenantName: null,
      },
    ]);
    const [header, row] = csv.trim().split("\r\n");
    expect(header).toContain(`"summary"`);
    expect(row).toContain(`"Added an integration “X”"`);
    expect(row).toContain(`"platform"`);
    expect(row).toContain("[redacted]");
    expect(row).not.toContain("leak");
  });
});

describe("audit filters", () => {
  const T = "11111111-1111-4111-8111-111111111111";

  it("validates, length-limits and drops tenants outside scope", () => {
    const f = parseAuditFilters({ tenant: "22222222-2222-4222-8222-222222222222", days: "9", actorKind: "root", targetType: "alert; drop", actor: "x".repeat(500), from: "2026-02-30", to: "2026-03-01", before: "-4" }, [T]);
    expect(f.tenantId).toBeUndefined();
    expect(f.sinceDays).toBe(30);
    expect(f.actorKind).toBeUndefined();
    expect(f.targetType).toBeUndefined();
    expect(f.actor).toHaveLength(120);
    expect(f.from).toBeUndefined();
    expect(f.to).toBe("2026-03-01");
    expect(f.before).toBeUndefined();
  });

  it("round-trips through the query string and orders a reversed range", () => {
    const f = parseAuditFilters({ tenant: T, actorKind: "ai", targetType: "incident", targetId: "abc", q: "note", from: "2026-03-05", to: "2026-03-01", before: "120" }, [T]);
    expect([f.from, f.to]).toEqual(["2026-03-01", "2026-03-05"]);
    const qs = auditQuery(f);
    expect(qs).not.toContain("before");
    expect(parseAuditFilters(Object.fromEntries(new URLSearchParams(qs)), [T])).toEqual({ ...f, before: undefined });
    expect(auditQuery(f, { before: 99 })).toContain("before=99");
  });
});

describe("isHermesActor", () => {
  it("is a service acting through the tuning API, or the identity named Hermes", () => {
    expect(isHermesActor({ action: "tuning.close", actorKind: "service" })).toBe(true);
    expect(isHermesActor({ action: "tuning.annotate", actorKind: "service" }, "Some agent")).toBe(true);
    expect(isHermesActor({ action: "noise_rule.create", actorKind: "service", detail: { via: "tuning_api" } })).toBe(true);
    expect(isHermesActor({ action: "api.request", actorKind: "service" }, "Hermes (prod)")).toBe(true);
    expect(isHermesActor({ action: "api.request", actorKind: "service" }, "hermes-prod")).toBe(true);
  });

  it("is never a person, and not other services", () => {
    expect(isHermesActor({ action: "tuning.undo", actorKind: "user" }, "Hermes Smith")).toBe(false);
    expect(isHermesActor({ action: "tuning.switch", actorKind: "user" })).toBe(false);
    expect(isHermesActor({ action: "noise_rule.create", actorKind: "user", detail: { via: "tuning_api" } })).toBe(false);
    expect(isHermesActor({ action: "api.request", actorKind: "service" }, "SIEM exporter")).toBe(false);
    expect(isHermesActor({ action: "api.request", actorKind: "service" }, "hermesian")).toBe(false);
    expect(isHermesActor({ action: "alert.update", actorKind: "service" }, null)).toBe(false);
  });
});
