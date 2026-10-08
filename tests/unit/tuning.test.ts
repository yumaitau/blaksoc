import { describe, expect, it } from "vitest";
import { scoreAlert } from "@/lib/risk/engine";
import { dispositionFactors, EMPTY_COUNTS, falsePositiveShare, type DispositionCounts } from "@/lib/tuning/disposition";
import { guardrailRefusal } from "@/lib/tuning/guardrails";
import { checkMemoryNotes, memoryDiff } from "@/lib/tuning/memory";
import { effectiveStatus, expiryFrom, firstMatch, globMatch, ruleMatches, shortHost, type NoiseRuleLike } from "@/lib/tuning/noise";
import { piiKind, stripControl } from "@/lib/tuning/pii";
import { PATTERN_ID, patternIdFor, pseudonymKey, tenantRefFor } from "@/lib/tuning/pseudonym";
import { ruleMetadata, safeToken } from "@/lib/tuning/rule-meta";

const counts = (c: Partial<DispositionCounts>): DispositionCounts => ({ ...EMPTY_COUNTS, ...c });
const NOW = new Date("2026-10-08T00:00:00Z");
const DAY = 86_400_000;

describe("disposition memory", () => {
  it("scores down a rule closed as false positive at least 80% of the time, from 5 decided alerts", () => {
    expect(dispositionFactors({ rule: counts({ falsePositive: 4 }), asset: null })).toEqual([]); // 4 samples: too few
    const [f] = dispositionFactors({ rule: counts({ falsePositive: 18, resolved: 2, other: 40 }), asset: null });
    expect(f).toMatchObject({ key: "disposition_fp", points: -13 });
    expect(f!.evidence).toBe("Closed as false positive 18 of 20 times in 90 days across this customer");
    expect(dispositionFactors({ rule: counts({ falsePositive: 7, resolved: 3 }), asset: null })).toEqual([]); // 70%
    expect(dispositionFactors({ rule: counts({ falsePositive: 5 }), asset: null })[0]!.points).toBe(-15);
    expect(dispositionFactors({ rule: counts({ falsePositive: 4, resolved: 1 }), asset: null })[0]!.points).toBe(-10);
  });

  it("prefers the host's own history once it has enough decisions", () => {
    const [f] = dispositionFactors({ rule: counts({ falsePositive: 2, resolved: 8 }), asset: counts({ falsePositive: 6 }) });
    expect(f!.evidence).toMatch(/6 of 6 times in 90 days on this host$/);
    expect(dispositionFactors({ rule: counts({ resolved: 10 }), asset: counts({ falsePositive: 3 }) })).toEqual([]);
  });

  it("raises risk when the rule led to escalations or containment, and open alerts are not evidence", () => {
    expect(dispositionFactors({ rule: counts({ escalated: 1 }), asset: null })).toEqual([expect.objectContaining({ key: "disposition_escalated", points: 6 })]);
    expect(dispositionFactors({ rule: counts({ escalated: 2, contained: 1 }), asset: null })[0]!.points).toBe(10);
    expect(falsePositiveShare(counts({ other: 100 }))).toBeNull();
  });

  it("feeds the risk score and never pushes it below zero", () => {
    const base = { severity: "low" as const, siemSeverity: 5, source: "wazuh", asset: null, identity: null, intel: null, attackTechniques: [], repeatCount: 0, cves: [], openIncidentOnAsset: false };
    const plain = scoreAlert(base);
    const tuned = scoreAlert({ ...base, disposition: { rule: counts({ falsePositive: 20 }), asset: null } });
    expect(plain.score).toBe(8);
    expect(tuned.score).toBe(0);
    expect(tuned.factors.at(-1)!.key).toBe("disposition_fp");
  });
});

const rule = (over: Partial<NoiseRuleLike> = {}): NoiseRuleLike => ({
  source: "wazuh", ruleId: "5710", assetId: null, hostname: null, titlePattern: null, status: "active", expiresAt: new Date(NOW.getTime() + DAY), ...over,
});
const alert = { source: "wazuh", ruleId: "5710", assetId: "a1", hostname: "WS-01.corp.example", title: "sshd: attempt to login using a non-existent user", severity: "low" };

describe("noise rule matching", () => {
  it("matches only live (active, unexpired) rules", () => {
    expect(ruleMatches(rule(), alert, NOW)).toBe(true);
    expect(ruleMatches(rule({ status: "proposed" }), alert, NOW)).toBe(false);
    expect(ruleMatches(rule({ status: "rejected" }), alert, NOW)).toBe(false);
    expect(ruleMatches(rule({ status: "expired" }), alert, NOW)).toBe(false);
    expect(ruleMatches(rule({ expiresAt: NOW }), alert, NOW)).toBe(false);
    expect(effectiveStatus(rule({ expiresAt: new Date(NOW.getTime() - 1) }), NOW)).toBe("expired");
  });

  it("needs the same source and rule id, and an alert without a rule id never matches", () => {
    expect(ruleMatches(rule({ source: "entra" }), alert, NOW)).toBe(false);
    expect(ruleMatches(rule({ ruleId: "5711" }), alert, NOW)).toBe(false);
    expect(ruleMatches(rule(), { ...alert, ruleId: null }, NOW)).toBe(false);
  });

  it("scopes to one host by asset, else by short host name, and fails closed on an unknown host", () => {
    expect(ruleMatches(rule({ assetId: "a1" }), alert, NOW)).toBe(true);
    expect(ruleMatches(rule({ assetId: "a2" }), alert, NOW)).toBe(false);
    expect(ruleMatches(rule({ hostname: "ws-01" }), { ...alert, assetId: null }, NOW)).toBe(true);
    expect(ruleMatches(rule({ hostname: "ws-02" }), { ...alert, assetId: null }, NOW)).toBe(false);
    expect(ruleMatches(rule({ assetId: "a1" }), { ...alert, assetId: null, hostname: null }, NOW)).toBe(false);
    expect(shortHost(" WS-01.Corp.Example ")).toBe("ws-01");
  });

  it("matches titles by case-insensitive glob without regular expressions", () => {
    expect(ruleMatches(rule({ titlePattern: "SSHD:*non-existent*" }), alert, NOW)).toBe(true);
    expect(ruleMatches(rule({ titlePattern: "*root*" }), alert, NOW)).toBe(false);
    expect(globMatch("a*b*c", "aXbYc")).toBe(true);
    expect(globMatch("a*b*c", "aXcYb")).toBe(false);
    expect(globMatch("ab", "abc")).toBe(false);
    expect(globMatch("*.*", "a.b")).toBe(true);
    expect(globMatch("a*a", "a")).toBe(false);
  });

  it("respects a severity cap and lets threat intel override any rule", () => {
    expect(ruleMatches(rule({ maxSeverity: "medium" }), alert, NOW)).toBe(true);
    expect(ruleMatches(rule({ maxSeverity: "medium" }), { ...alert, severity: "high" }, NOW)).toBe(false);
    expect(ruleMatches(rule({ maxSeverity: "medium" }), { ...alert, severity: null }, NOW)).toBe(false);
    expect(firstMatch([rule()], { ...alert, intelVerdict: "malicious" }, NOW)).toBeNull();
    expect(firstMatch([rule({ status: "proposed" }), rule({ ruleId: "5710" })], alert, NOW)).not.toBeNull();
  });

  it("bounds expiry to 1–180 whole days, 30 by default", () => {
    expect(expiryFrom(undefined, NOW).getTime() - NOW.getTime()).toBe(30 * DAY);
    expect(expiryFrom(180, NOW).getTime() - NOW.getTime()).toBe(180 * DAY);
    for (const bad of [0, 181, 1.5, -3, Number.NaN]) expect(() => expiryFrom(bad, NOW)).toThrow(RangeError);
  });
});

describe("tuning guardrails", () => {
  it("needs 10 human closures, 80% false positives and 30 quiet days", () => {
    expect(guardrailRefusal({ humanClosed: 9, humanFalsePositive: 9, escalatedRecently: 0 })).toMatch(/at least 10/);
    expect(guardrailRefusal({ humanClosed: 10, humanFalsePositive: 7, escalatedRecently: 0 })).toMatch(/70%/);
    expect(guardrailRefusal({ humanClosed: 10, humanFalsePositive: 8, escalatedRecently: 1 })).toMatch(/escalated/);
    expect(guardrailRefusal({ humanClosed: 10, humanFalsePositive: 8, escalatedRecently: 0 })).toBeNull();
  });
});

describe("what the tuning agent may see", () => {
  it("takes static rule metadata only, never descriptions", () => {
    const meta = ruleMetadata(
      { rule: { level: 5, description: "Login by alice@wattle.example on ws-01", groups: ["sshd", "alice@wattle.example", "ws-01.corp.local", "10.1.2.3"], mitre: { id: ["T1110.001", "not-a-technique"] } }, decoder: { name: "sshd" }, full_log: "alice" },
      ["T1078"],
    );
    expect(meta).toEqual({ level: 5, groups: ["sshd"], mitre: ["T1110.001", "T1078"], decoder: "sshd" });
    expect(JSON.stringify(meta)).not.toMatch(/alice|ws-01|10\.1/);
    expect(ruleMetadata(null)).toEqual({ level: null, groups: [], mitre: [], decoder: null });
  });

  it("hands out rule ids and sources only when they are identifiers", () => {
    expect(safeToken("5710")).toBe("5710");
    expect(safeToken("google.login.suspicious")).toBe("google.login.suspicious");
    expect(safeToken("ws-01.corp.local")).toBeNull();
    expect(safeToken("10.0.0.1")).toBeNull();
    expect(safeToken("fe80::1")).toBeNull();
    expect(safeToken("bob@example.com")).toBeNull();
  });

  it("gives stable, opaque pattern ids and tenant pseudonyms", () => {
    const key = pseudonymKey("test-secret-test-secret-test-secret");
    const id = patternIdFor(key, "t1", "wazuh", "5710");
    expect(id).toMatch(PATTERN_ID);
    expect(patternIdFor(key, "t1", "wazuh", "5710")).toBe(id);
    expect(patternIdFor(key, "t2", "wazuh", "5710")).not.toBe(id);
    expect(patternIdFor(pseudonymKey("another-secret-another-secret-xx"), "t1", "wazuh", "5710")).not.toBe(id);
    expect(tenantRefFor(key, "t1")).toMatch(/^T-[0-9a-f]{6}$/);
  });
});

describe("agent memory", () => {
  const ID = "0b9f0c0e-1d2a-4c1b-9a7e-2f1d3c4b5a69";

  it("refuses notes that look like they name hosts, addresses or emails", () => {
    const bad = ["Seen from 10.0.4.7", "user bob@wattle.example", "dc01.corp.local noisy", "fe80::1ff:fe23:4567:890a"];
    for (const text of bad) expect(checkMemoryNotes([{ kind: "model", text }]).ok, text).toBe(false);
    const ok = checkMemoryNotes([{ kind: "outcome", text: "Rule google.login.suspicious and T1059.001 fire together at 02:00:00 nightly; version 2.1 benign." }]);
    expect(ok.ok).toBe(true);
    expect(piiKind("10:30:00")).toBeNull();
  });

  it("caps notes, checks ids, ignores analysts' notes and strips control characters", () => {
    expect(checkMemoryNotes(Array.from({ length: 501 }, () => ({ kind: "model" as const, text: "x" }))).ok).toBe(false);
    expect(checkMemoryNotes([{ id: ID, kind: "model", text: "x" }, { id: ID, kind: "model", text: "y" }]).ok).toBe(false);
    expect(checkMemoryNotes([{ id: "not-an-id", kind: "model", text: "x" }]).ok).toBe(false);
    expect(checkMemoryNotes([{ kind: "model", text: "x".repeat(2001) }]).ok).toBe(false);
    expect(checkMemoryNotes([{ kind: "human", text: "anything at all, even 10.0.0.1" }])).toEqual({ ok: true, notes: [] });
    expect(stripControl("a\u0000b\u202Ec\r\nd")).toBe("abc\nd");
  });

  it("summarises a memory change as counts", () => {
    const before = [{ id: "a", kind: "model", text: "1" }, { id: "b", kind: "model", text: "2" }];
    expect(memoryDiff(before, [{ id: "a", kind: "model", text: "1" }, { id: null, kind: "outcome", text: "3" }])).toEqual({ added: 1, removed: 1, changed: 0, unchanged: 1 });
    expect(memoryDiff(before, [{ id: "a", kind: "outcome", text: "1" }])).toEqual({ added: 0, removed: 1, changed: 1, unchanged: 0 });
  });
});
