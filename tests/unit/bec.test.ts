import { describe, expect, it } from "vitest";
import { correlateImpossibleTravel, correlateMfaFatigue, paymentKeywords, SUSPECTED_BEC_PLAYBOOK, type MfaPoint, type SignInPoint } from "@/lib/detections/bec";

const t = (iso: string) => iso;

describe("impossible travel", () => {
  const finance = (id: string, country: string, at: string): SignInPoint => ({ id, user: "finance@wattle.example", country, ip: "203.0.113.10", at });

  it("fires when mailbox activity sits between two countries inside two hours", () => {
    const hits = correlateImpossibleTravel(
      [finance("a", "AU", t("2026-09-29T00:00:00.000Z")), finance("b", "US", t("2026-09-29T01:30:00.000Z"))],
      new Set(["finance@wattle.example"]),
    );
    expect(hits.map((h) => h.id)).toEqual(["travel:a:b"]);
  });

  it("stays quiet for the same country, a long gap, or no mailbox use", () => {
    const pair = [finance("a", "AU", t("2026-09-29T00:00:00.000Z")), finance("b", "AU", t("2026-09-29T01:00:00.000Z"))];
    expect(correlateImpossibleTravel(pair, new Set(["finance@wattle.example"]))).toEqual([]);
    const far = [finance("a", "AU", t("2026-09-29T00:00:00.000Z")), finance("b", "US", t("2026-09-29T05:00:00.000Z"))];
    expect(correlateImpossibleTravel(far, new Set(["finance@wattle.example"]))).toEqual([]);
    const quiet = [finance("a", "AU", t("2026-09-29T00:00:00.000Z")), finance("b", "US", t("2026-09-29T01:00:00.000Z"))];
    expect(correlateImpossibleTravel(quiet, new Set())).toEqual([]);
  });
});

describe("MFA fatigue", () => {
  function point(id: string, at: string, denied: boolean): MfaPoint {
    return { id, user: "reception@wattle.example", at, denied, success: !denied };
  }

  it("needs three denials then a success inside an hour", () => {
    const hits = correlateMfaFatigue([
      point("d1", "2026-09-29T00:00:00.000Z", true),
      point("d2", "2026-09-29T00:10:00.000Z", true),
      point("d3", "2026-09-29T00:20:00.000Z", true),
      point("ok", "2026-09-29T00:30:00.000Z", false),
    ]);
    expect(hits).toEqual([{ id: "mfa:ok", user: "reception@wattle.example", denied: 3, successId: "ok", at: "2026-09-29T00:30:00.000Z" }]);
    const short = correlateMfaFatigue([
      point("d1", "2026-09-29T00:00:00.000Z", true),
      point("d2", "2026-09-29T00:10:00.000Z", true),
      point("ok", "2026-09-29T00:20:00.000Z", false),
    ]);
    expect(short).toEqual([]);
  });
});

describe("payment keywords", () => {
  it("matches the invoice and remittance words and ignores a newsletter", () => {
    expect(paymentKeywords("Please pay this invoice via EFT")).toEqual(expect.arrayContaining(["invoice", "eft"]));
    expect(paymentKeywords("weekly newsletter")).toEqual([]);
  });
});

describe("Suspected BEC playbook", () => {
  it("is disabled and walks enrich, incident, approval, containment, and the customer tasks", () => {
    expect(SUSPECTED_BEC_PLAYBOOK.enabled).toBe(false);
    expect(SUSPECTED_BEC_PLAYBOOK.trigger).toEqual({ event: "alert.created", conditions: [{ field: "alert.category", op: "eq", value: "bec" }] });
    const actions = SUSPECTED_BEC_PLAYBOOK.steps.map((s) => s.action);
    expect(actions).toEqual(["intel.enrich", "incident.create", "notify", "approval.request", "revoke_sessions", "disable_identity", "remove_inbox_rule", "task.create"]);
    const titles = SUSPECTED_BEC_PLAYBOOK.steps.find((s) => s.action === "task.create")!.params!.titles as string[];
    expect(titles.some((title) => /bank/i.test(title))).toBe(true);
    expect(titles.some((title) => /ReportCyber/.test(title))).toBe(true);
    expect(titles.some((title) => /payment/i.test(title))).toBe(true);
    expect(titles.some((title) => /Notifiable Data Breach/.test(title))).toBe(true);
  });
});
