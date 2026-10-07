import { describe, expect, it } from "vitest";
import { evaluateRule, evaluateRules, matches, validateRule, type CorrelationEvent, type CorrelationRule } from "@/lib/correlation/engine";
import { alertFromFinding, contributingIds, eventFromAlert, type AlertForCorrelation } from "@/lib/correlation/events";
import { MAX_REASON_EDGES, planGroups, type GroupableAlert } from "@/lib/correlation/grouping";
import { ACCOUNT_TAKEOVER, BUILTIN_RULES, HOST_RISK_ACCUMULATION, SOURCE_FANOUT, USER_RISK_ACCUMULATION } from "@/lib/correlation/rules";

const MIN = 60_000;
const T0 = Date.parse("2026-10-01T00:00:00.000Z");
const ev = (id: string, minutes: number, fields: Record<string, unknown>): CorrelationEvent => ({ id, at: T0 + minutes * MIN, fields: { user: "alice@wattle.example", ...fields } });

function base(clause: CorrelationRule["clause"], extra: Partial<CorrelationRule> = {}): CorrelationRule {
  return { id: "test-rule", version: 1, title: "Test rule", description: "", severity: "high", category: "test", techniques: [], stage: "alerts", enabledByDefault: true, groupBy: ["user"], clause, eventType: "test", ...extra };
}

/** Reverse and interleave so order of arrival never matters. */
function shuffled<T>(xs: T[]): T[] {
  const r = [...xs].reverse();
  return [...r.filter((_, i) => i % 2), ...r.filter((_, i) => !(i % 2))];
}

describe("built-in rules", () => {
  it("are all structurally valid with unique ids", () => {
    for (const r of BUILTIN_RULES) expect(validateRule(r), r.id).toEqual([]);
    expect(new Set(BUILTIN_RULES.map((r) => r.id)).size).toBe(BUILTIN_RULES.length);
  });

  it("validation catches a bad sequence", () => {
    const bad = base({
      type: "sequence", id: "s", label: "s", within: 0,
      steps: [{ id: "a", label: "a", when: [{ label: "a", match: {}, differsFrom: { step: "b", fields: ["x"] } }] }, { id: "b", label: "b", when: [{ label: "b", match: {}, count: 2 }] }],
    });
    expect(validateRule(bad)).toEqual(["within must be positive", "step a: differsFrom must name an earlier step", "final step b must take exactly one event"]);
  });
});

describe("field matching", () => {
  const e = ev("x", 0, { event_type: "Inbox_Rule", risk_score: 40, techniques: ["T1078", "T1114.003"] });
  it("compares strings case-insensitively and supports lists, contains, ranges, exists and not", () => {
    expect(matches(e, { event_type: "inbox_rule" })).toBe(true);
    expect(matches(e, { event_type: ["oauth_consent", "inbox_rule"] })).toBe(true);
    expect(matches(e, { techniques: "T1114.003" })).toBe(true);
    expect(matches(e, { techniques: { contains: "t1114" } })).toBe(true);
    expect(matches(e, { risk_score: { gte: 40 } })).toBe(true);
    expect(matches(e, { risk_score: { lte: 39 } })).toBe(false);
    expect(matches(e, { country: { exists: false } })).toBe(true);
    expect(matches(e, { event_type: { not: "inbox_rule" } })).toBe(false);
    expect(matches(e, [{ event_type: "nope" }, { risk_score: 40 }])).toBe(true);
  });
});

describe("sequence clause", () => {
  const rule = base({
    type: "sequence", id: "seq", label: "A then B", within: 30 * MIN,
    steps: [
      { id: "a", label: "Step A", when: [{ label: "A", match: { event_type: "a" } }] },
      { id: "b", label: "Step B", when: [{ label: "B", match: { event_type: "b" } }] },
    ],
  });

  it("fires on A then B inside the window and names the events per step", () => {
    const [f, ...rest] = evaluateRule(rule, [ev("a1", 0, { event_type: "a" }), ev("noise", 5, { event_type: "c" }), ev("b1", 20, { event_type: "b" })]);
    expect(rest).toEqual([]);
    expect(f!.matches.map((m) => [m.clause, m.events.map((e) => e.id)])).toEqual([["seq.a", ["a1"]], ["seq.b", ["b1"]]]);
    expect(f!.entity).toEqual({ user: "alice@wattle.example" });
    expect(f!.eventIds).toEqual(["a1", "b1"]);
    expect(f!.explanation[0]).toBe("Test rule for user alice@wattle.example: 2 steps in order within 30m.");
    expect(f!.explanation[1]).toContain("[a1]");
  });

  it("does not fire out of order, outside the window, or across entities", () => {
    expect(evaluateRule(rule, [ev("b1", 0, { event_type: "b" }), ev("a1", 10, { event_type: "a" })])).toEqual([]);
    expect(evaluateRule(rule, [ev("a1", 0, { event_type: "a" }), ev("b1", 31, { event_type: "b" })])).toEqual([]);
    expect(evaluateRule(rule, [ev("a1", 0, { event_type: "a" }), ev("b1", 10, { event_type: "b", user: "bob@wattle.example" })])).toEqual([]);
  });

  it("gives one finding per final event with a stable dedupe key, whatever the input order", () => {
    const events = [ev("a1", 0, { event_type: "a" }), ev("b1", 10, { event_type: "b" }), ev("b2", 15, { event_type: "b" })];
    const once = evaluateRule(rule, events);
    expect(once.map((f) => f.anchorId)).toEqual(["b1", "b2"]);
    expect(evaluateRule(rule, shuffled(events))).toEqual(once);
    expect(new Set(once.map((f) => f.dedupeKey)).size).toBe(2);
  });
});

describe("count clause", () => {
  it("fires at the threshold of distinct values and suppresses repeats inside the window", () => {
    const rule = { ...SOURCE_FANOUT, groupBy: ["src_ip"] };
    const hit = (id: string, m: number, host: string) => ({ id, at: T0 + m * MIN, fields: { src_ip: "198.51.100.7", host, summary: `alert on ${host}` } });
    const findings = evaluateRule(rule, [hit("1", 0, "web-01"), hit("2", 5, "web-01"), hit("3", 10, "db-01"), hit("4", 20, "app-01"), hit("5", 25, "file-01")]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.anchorId).toBe("4");
    expect(findings[0]!.matches[0]!.events.map((e) => e.id)).toEqual(["1", "2", "3", "4"]);
    expect(findings[0]!.matches[0]!.note).toBe("3 distinct host within 1h (threshold 3): app-01, db-01, web-01");
  });

  it("stays quiet below the threshold or when the events spread past the window", () => {
    const rule = base({ type: "count", id: "n", label: "Failures", match: { event_type: "fail" }, threshold: 3, within: 10 * MIN });
    expect(evaluateRule(rule, [ev("1", 0, { event_type: "fail" }), ev("2", 5, { event_type: "fail" })])).toEqual([]);
    expect(evaluateRule(rule, [ev("1", 0, { event_type: "fail" }), ev("2", 6, { event_type: "fail" }), ev("3", 12, { event_type: "fail" })])).toEqual([]);
    expect(evaluateRule(rule, [ev("1", 0, { event_type: "fail" }), ev("2", 6, { event_type: "fail" }), ev("3", 9, { event_type: "fail" })])).toHaveLength(1);
  });
});

describe("absence clause", () => {
  const rule = base({
    type: "absence", id: "abs", label: "Unacknowledged", within: 60 * MIN,
    trigger: { label: "Isolation requested", match: { event_type: "isolate_requested" } },
    missing: { label: "Isolation confirmed", match: { event_type: "isolate_confirmed" }, sameFields: ["host"] },
  });
  const req = ev("r1", 0, { event_type: "isolate_requested", host: "pc-07" });

  it("fires only once the window has closed with nothing matching", () => {
    expect(evaluateRule(rule, [req], T0 + 30 * MIN)).toEqual([]);
    expect(evaluateRule(rule, [req])).toEqual([]);
    const [f] = evaluateRule(rule, [req], T0 + 61 * MIN);
    expect(f!.matches).toEqual([
      { clause: "abs.trigger", label: "Isolation requested", events: [{ id: "r1", at: new Date(T0).toISOString(), summary: "isolate_requested" }] },
      { clause: "abs.missing", label: "Isolation confirmed", events: [], note: `no matching event between ${new Date(T0).toISOString()} and ${new Date(T0 + 60 * MIN).toISOString()}` },
    ]);
    expect(f!.lastAt).toBe(T0 + 60 * MIN);
  });

  it("is satisfied by a follow-up for the same host, not for another", () => {
    expect(evaluateRule(rule, [req, ev("c1", 40, { event_type: "isolate_confirmed", host: "pc-07" })], T0 + 120 * MIN)).toEqual([]);
    expect(evaluateRule(rule, [req, ev("c1", 40, { event_type: "isolate_confirmed", host: "pc-99" })], T0 + 120 * MIN)).toHaveLength(1);
  });
});

describe("risk accumulation clause", () => {
  it("sums alert risk per user and lists the alerts that added up", () => {
    const events = [40, 30, 50, 45, 20].map((risk, i) => ev(`r${i}`, i * 60, { risk_score: risk }));
    const findings = evaluateRule(USER_RISK_ACCUMULATION, events);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.anchorId).toBe("r3");
    expect(findings[0]!.matches[0]!.note).toBe("risk_score total 165 within 24h (threshold 150): r0=40, r1=30, r2=50, r3=45");
  });

  it("does not add up alerts that fall outside the window", () => {
    const events = [80, 80].map((risk, i) => ev(`r${i}`, i * 25 * 60, { risk_score: risk }));
    expect(evaluateRule(USER_RISK_ACCUMULATION, events)).toEqual([]);
  });
});

describe("account takeover rule", () => {
  const attack: CorrelationEvent[] = [
    ev("baseline", -3 * 24 * 60, { event_type: "signin", outcome: "success", country: "AU", device: "laptop-01", summary: "sign-in from AU on laptop-01" }),
    ev("push1", 0, { event_type: "mfa_denied", summary: "MFA prompt denied" }),
    ev("push2", 2, { event_type: "mfa_denied", summary: "MFA prompt denied" }),
    ev("push3", 4, { event_type: "mfa_denied", summary: "MFA prompt denied" }),
    ev("push4", 6, { event_type: "mfa_denied", summary: "MFA prompt denied" }),
    ev("approve", 8, { event_type: "mfa_success", summary: "MFA prompt approved" }),
    ev("login", 8, { event_type: "signin", outcome: "success", country: "NG", device: "unknown", summary: "sign-in from NG" }),
    ev("noise", 30, { event_type: "file_download", summary: "file download" }),
    ev("rule", 45, { event_type: "inbox_rule", summary: "inbox rule deletes 'invoice' mail" }),
  ];

  it("fires on push spam, then a new-country sign-in, then an inbox rule, listing each contributing event", () => {
    const findings = evaluateRule(ACCOUNT_TAKEOVER, attack);
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.matches.map((m) => [m.clause, m.label, m.events.map((e) => e.id)])).toEqual([
      ["ato.pressure", "Credential pressure: MFA push spam (3+ denied prompts)", ["push1", "push2", "push3", "push4"]],
      ["ato.access", "Access from a new location or device: successful sign-in from a new country or device", ["login"]],
      ["ato.persistence", "Mailbox persistence or app consent: inbox rule or forwarding", ["rule"]],
    ]);
    expect(f.eventIds).toEqual(["login", "push1", "push2", "push3", "push4", "rule"]);
    expect(f.explanation).toEqual([
      "Account takeover: credential pressure, new-location access, then persistence for user alice@wattle.example: 3 steps in order within 24h.",
      `Credential pressure: MFA push spam (3+ denied prompts): ${["push1", "push2", "push3", "push4"].map((id, i) => `MFA prompt denied at ${new Date(T0 + i * 2 * MIN).toISOString()} [${id}]`).join("; ")}`,
      `Access from a new location or device: successful sign-in from a new country or device: sign-in from NG at ${new Date(T0 + 8 * MIN).toISOString()} [login]`,
      `Mailbox persistence or app consent: inbox rule or forwarding: inbox rule deletes 'invoice' mail at ${new Date(T0 + 45 * MIN).toISOString()} [rule]`,
    ]);
  });

  it("stays quiet when the sign-in is from a known place, or the order is wrong", () => {
    const known = attack.map((e) => (e.id === "login" ? { ...e, fields: { ...e.fields, country: "AU", device: "laptop-01" } } : e));
    expect(evaluateRule(ACCOUNT_TAKEOVER, known)).toEqual([]);
    const early = attack.map((e) => (e.id === "rule" ? { ...e, at: T0 - 60 * MIN } : e));
    expect(evaluateRule(ACCOUNT_TAKEOVER, early)).toEqual([]);
    const fewPushes = attack.filter((e) => e.id !== "push3" && e.id !== "push4");
    expect(evaluateRule(ACCOUNT_TAKEOVER, fewPushes)).toEqual([]);
  });

  it("fires on stored alerts: MFA fatigue alert, impossible travel alert, OAuth consent alert", () => {
    const alert = (id: string, minutes: number, eventType: string, title: string): AlertForCorrelation => ({
      id, source: "entra", ruleId: eventType, title, category: "bec", severity: "high", riskScore: 50, userName: "Alice@Wattle.example", assetId: null, hostname: null,
      attackTechniques: [], raw: { eventType }, occurredAt: new Date(T0 + minutes * MIN),
    });
    const events = [alert("al-mfa", 0, "mfa_fatigue", "MFA fatigue"), alert("al-travel", 0, "impossible_travel", "Impossible travel"), alert("al-oauth", 90, "oauth_consent", "Suspicious OAuth consent for mail")].map(eventFromAlert);
    const [f] = evaluateRule(ACCOUNT_TAKEOVER, events);
    expect(f!.matches.map((m) => m.events.map((e) => e.id))).toEqual([["al-mfa"], ["al-travel"], ["al-oauth"]]);
    const raised = alertFromFinding(ACCOUNT_TAKEOVER, f!);
    expect(raised).toMatchObject({ externalId: f!.dedupeKey, ruleId: "account-takeover", severity: "critical", userName: "alice@wattle.example", category: "bec" });
    expect(raised.description).toBe(f!.explanation.join("\n"));
    expect(contributingIds(raised.raw).sort()).toEqual(["al-mfa", "al-oauth", "al-travel"]);
    // Both alerts come from the same sign-in, so they share a timestamp; id order must not decide the outcome.
    const swapped = events.map((e) => (e.id === "al-mfa" ? { ...e, id: "zz-mfa" } : e));
    expect(evaluateRule(ACCOUNT_TAKEOVER, swapped).map((x) => x.matches.map((m) => m.events.map((e) => e.id)))).toEqual([[["zz-mfa"], ["al-travel"], ["al-oauth"]]]);
  });

  it("raises one finding per user per day, not one per persistence event", () => {
    const more = [...attack, ev("rule2", 50, { event_type: "oauth_consent", summary: "OAuth consent" })];
    expect(evaluateRule(ACCOUNT_TAKEOVER, more).map((f) => f.anchorId)).toEqual(["rule"]);
  });
});

describe("evaluateRules", () => {
  it("is deterministic over shuffled input", () => {
    const events = [
      ...[60, 60, 60].map((r, i) => ev(`risk${i}`, i * 10, { risk_score: r })),
      ev("p1", 0, { event_type: "mfa_denied" }), ev("p2", 1, { event_type: "mfa_denied" }), ev("p3", 2, { event_type: "mfa_denied" }),
      ev("travel", 5, { event_type: "impossible_travel" }), ev("grant", 9, { event_type: "oauth_consent" }),
    ];
    const rules = BUILTIN_RULES.filter((r) => r.stage === "alerts");
    const a = evaluateRules(rules, events, T0 + 48 * 60 * MIN);
    expect(a.map((f) => f.ruleId).sort()).toEqual(["account-takeover", "user-risk-accumulation"]);
    expect(evaluateRules(rules, shuffled(events), T0 + 48 * 60 * MIN)).toEqual(a);
  });
});

describe("automatic grouping", () => {
  const tactics = { T1621: ["credential-access"], T1078: ["initial-access", "persistence"], "T1114.003": ["collection"], T1528: ["credential-access"], T1046: ["discovery"] };
  const a = (id: string, minutes: number, techniques: string[], extra: Partial<GroupableAlert> = {}): GroupableAlert => ({
    id, occurredAt: T0 + minutes * MIN, userName: "alice@wattle.example", assetId: null, techniques, incidentId: null, ...extra,
  });
  const input = [
    a("mfa", 0, ["T1621"]),
    a("oauth", 30, ["T1528"]),
    a("travel", 60, ["T1078"]),
    a("other-user", 10, ["T1621"], { userName: "bob@wattle.example" }),
    a("scan", 20, ["T1046"]),
    a("late", 20 * 60, ["T1528"]),
  ];

  it("groups by entity, window and shared tactic, and records why", () => {
    const plans = planGroups(input, { windowMs: 6 * 60 * MIN, tactics });
    expect(plans).toHaveLength(1);
    expect(plans[0]).toMatchObject({ groupingKey: "grp:mfa", incidentId: null, alertIds: ["mfa", "oauth"] });
    expect(plans[0]!.reason).toMatchObject({ entities: ["user:alice@wattle.example"], tactics: ["credential-access"], techniques: [] });
    expect(plans[0]!.reason.edges).toEqual([{ a: "mfa", b: "oauth", entities: ["user:alice@wattle.example"], techniques: [], tactics: ["credential-access"], correlated: false }]);
    expect(plans[0]!.reason.summary).toBe("same user:alice@wattle.example; within 6h; shared ATT&CK credential-access");
  });

  it("is deterministic: the same alerts in any order give the same groups", () => {
    const once = planGroups(input, { windowMs: 6 * 60 * MIN, tactics });
    expect(planGroups(shuffled(input), { windowMs: 6 * 60 * MIN, tactics })).toEqual(once);
    expect(planGroups([...input, ...input], { windowMs: 6 * 60 * MIN, tactics })).toEqual(once);
  });

  it("joins an open incident one of the group is already in, and follows correlation links past the window", () => {
    const plans = planGroups(
      [
        a("mfa", 0, ["T1621"], { incidentId: "inc-1" }),
        a("oauth", 30, ["T1528"]),
        a("corr", 30 * 60, ["T1078"], { relatedIds: ["mfa", "travel-old"] }),
      ],
      { windowMs: 6 * 60 * MIN, tactics },
    );
    expect(plans).toEqual([expect.objectContaining({ groupingKey: null, incidentId: "inc-1", alertIds: ["oauth", "corr"] })]);
    expect(plans[0]!.reason.edges.find((e) => e.b === "corr")).toMatchObject({ a: "mfa", correlated: true });
  });

  it("never pulls two alerts that are both already in incidents together", () => {
    const plans = planGroups([a("x", 0, ["T1621"], { incidentId: "inc-1" }), a("y", 5, ["T1621"], { incidentId: "inc-2" })], { windowMs: 6 * 60 * MIN, tactics });
    expect(plans).toEqual([]);
  });
});

describe("busy entities", () => {
  it("evaluates a window rule over thousands of events on one host without building every window", () => {
    // A new host's benchmark scan: thousands of scored alerts inside one risk window. Building each anchor's
    // evidence eagerly took gigabytes of heap in production; only the emitted finding should be built.
    const events = Array.from({ length: 5000 }, (_, i) => ({ id: `e${i}`, at: T0 + i * 10_000, fields: { host: "web-01", risk_score: 25, summary: `check ${i}` } }));
    const rule = { ...USER_RISK_ACCUMULATION, id: "host-risk", groupBy: ["host"] };
    const started = performance.now();
    const findings = evaluateRule(rule, events);
    expect(performance.now() - started).toBeLessThan(2000);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]!.explanation[0]).toContain("host web-01");
  });
});

describe("grouping a busy host", () => {
  it("joins thousands of related alerts with a bounded reason", () => {
    // Every pair in the window used to become a stored edge: millions for one benchmark scan.
    const alerts: GroupableAlert[] = Array.from({ length: 6000 }, (_, i) => ({ id: `s${String(i).padStart(5, "0")}`, occurredAt: T0 + i * 15_000, userName: null, assetId: "host-1", techniques: ["T1078"], incidentId: null }));
    const started = performance.now();
    const plans = planGroups(alerts, { windowMs: 6 * 60 * MIN, tactics: { T1078: ["initial-access"] } });
    expect(performance.now() - started).toBeLessThan(2000);
    expect(plans).toHaveLength(1);
    expect(plans[0]!.alertIds).toHaveLength(6000);
    expect(plans[0]!.reason.edges).toHaveLength(MAX_REASON_EDGES);
    expect(plans[0]!.reason.edgeCount).toBe(5999);
  });
});

describe("risk accumulation signal", () => {
  it("does not count benchmark (SCA) or informational alerts", () => {
    const at = (i: number) => T0 + i * MIN;
    const noise = Array.from({ length: 40 }, (_, i) => ({ id: `n${i}`, at: at(i), fields: { host: "web-01", risk_score: 25, category: i % 2 ? "sca" : "pam", severity: i % 2 ? "medium" : "informational" } }));
    expect(evaluateRule(HOST_RISK_ACCUMULATION, noise)).toEqual([]);
    const real = Array.from({ length: 7 }, (_, i) => ({ id: `r${i}`, at: at(100 + i), fields: { host: "web-01", risk_score: 25, category: "audit", severity: "medium" } }));
    expect(evaluateRule(HOST_RISK_ACCUMULATION, [...noise, ...real])).toHaveLength(1);
  });
});

describe("source fan-out signal", () => {
  it("ignores routine informational logins from an orchestration host", () => {
    const logins = ["web-01", "db-01", "app-01", "cache-01"].map((host, i) => ({ id: `l${i}`, at: T0 + i * MIN, fields: { src_ip: "172.31.36.25", host, severity: "informational", category: "syslog" } }));
    expect(evaluateRule(SOURCE_FANOUT, logins)).toEqual([]);
    const attacks = logins.map((e) => ({ ...e, id: `x${e.id}`, fields: { ...e.fields, severity: "medium", category: "sshd" } }));
    expect(evaluateRule(SOURCE_FANOUT, attacks)).toHaveLength(1);
  });
});

describe("grouping correlation findings", () => {
  it("puts a finding in the same incident as other alerts on its entity, without a shared technique", () => {
    const base = { userName: null, incidentId: null };
    const plans = planGroups(
      [
        { ...base, id: "brute", occurredAt: T0, userName: "kim", assetId: "host-1", techniques: ["T1110"] },
        { ...base, id: "user-risk", occurredAt: T0 + MIN, userName: "kim", assetId: null, techniques: [], relatedIds: ["low-1", "low-2"] },
        { ...base, id: "host-risk", occurredAt: T0 + MIN, assetId: "host-1", techniques: [], relatedIds: ["low-1"] },
        { ...base, id: "elsewhere", occurredAt: T0 + MIN, assetId: "host-2", techniques: ["T1110"] },
      ],
      { windowMs: 6 * 60 * MIN, tactics: {}, minAlerts: 1 },
    );
    expect(plans.map((p) => p.alertIds)).toEqual([["brute", "host-risk", "user-risk"], ["elsewhere"]]);
  });
});

describe("singleton incidents", () => {
  it("describe a lone qualifying alert plainly", () => {
    const [plan] = planGroups([{ id: "solo", occurredAt: T0, userName: null, assetId: "host-1", techniques: [], incidentId: null }], { windowMs: 6 * 60 * MIN, tactics: {}, minAlerts: 1 });
    expect(plan!.reason.summary).toBe("single alert; no related alerts within 6h");
  });
});
