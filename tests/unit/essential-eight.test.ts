import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { evidenceFromTelemetry, type TelemetrySnapshot } from "@/lib/essential-eight/evidence";
import { buildAssessmentReport } from "@/lib/essential-eight/report";
import { answerIds, DISCLAIMER, REQUIREMENTS, STRATEGIES, type StrategyId } from "@/lib/essential-eight/requirements";
import { levelTrend, scoreEssentialEight, type AssessmentResult, type Level } from "@/lib/essential-eight/score";
import { toPdf } from "@/lib/reports/export";

const AT = new Date("2026-09-01T00:00:00.000Z");

function pdfPlain(bytes: Uint8Array) {
  const raw = Buffer.from(bytes);
  const latin = raw.toString("latin1");
  let out = "";
  const marker = /stream\r?\n/g;
  let match: RegExpExecArray | null;
  while ((match = marker.exec(latin))) {
    const start = match.index + match[0].length;
    const end = latin.indexOf("endstream", start);
    let chunk: Buffer = raw.subarray(start, end);
    if (chunk[chunk.length - 1] === 0x0a) chunk = chunk.subarray(0, -1);
    try {
      chunk = Buffer.from(inflateSync(chunk));
    } catch {
      // already plain
    }
    out += chunk.toString("latin1").replace(/<([0-9A-Fa-f\s]+)>/g, (_, hex: string) => Buffer.from(hex.replace(/\s/g, ""), "hex").toString("latin1"));
  }
  return out;
}
const DAY = 86_400_000;

function yesAll(): Record<string, "yes" | "no"> {
  return Object.fromEntries(answerIds().map((id) => [id, "yes"]));
}

function rate(answers: Record<string, "yes" | "no">, evidence: Parameters<typeof scoreEssentialEight>[0]["evidence"] = []) {
  return scoreEssentialEight({ answers, evidence, assessedAt: AT, owner: "Ava Chen", cadenceDays: 90 });
}

function level(result: ReturnType<typeof rate>, strategy: StrategyId) {
  return result.ratings.find((row) => row.strategy === strategy)!;
}

const emptySnap = (): TelemetrySnapshot => ({ assets: [], vulns: [], identities: [], connectors: [], officeMacros: null });

describe("essential eight scoring", () => {
  it("rates every strategy ML3 when every answer is yes and nothing contradicts it", () => {
    const result = rate(yesAll());
    expect(result.disclaimer).toBe(DISCLAIMER);
    expect(result.disclaimer).toContain("not an ACSC-endorsed audit");
    expect(result.nextDue.toISOString()).toBe(new Date(AT.getTime() + 90 * DAY).toISOString());
    for (const strategy of STRATEGIES) {
      const row = level(result, strategy.id);
      expect(row.level).toBe(3);
      for (const line of row.lines) {
        expect(line.answer).toBe("yes");
        expect(line.evidence.detail.length).toBeGreaterThan(0);
      }
    }
    expect(result.remediation).toEqual([]);
  });

  for (const strategy of STRATEGIES) {
    it(`${strategy.label} drops to ML0 when one Maturity Level One answer is no`, () => {
      const answers = yesAll();
      const requirement = REQUIREMENTS.find((row) => row.strategy === strategy.id && row.minLevel === 1)!;
      answers[requirement.answerId] = "no";
      const result = rate(answers);
      const row = level(result, strategy.id);
      const line = row.lines.find((item) => item.id === requirement.id)!;
      expect(row.level).toBe(0);
      expect(line.answer).toBe("no");
      expect(line.met).toBe(false);
      expect(line.evidence.detail.length).toBeGreaterThan(0);
      expect(result.remediation.some((item) => item.requirementId === requirement.id)).toBe(true);
      expect(result.remediation.find((item) => item.requirementId === requirement.id)).toMatchObject({
        owner: "Ava Chen",
        priority: 1,
        dueAt: new Date(AT.getTime() + 14 * DAY).toISOString(),
      });
      expect(result.remediation.some((item) => item.requirementId === "pa-office-48h" && strategy.id === "patch_applications")).toBe(false);
    });

    it(`${strategy.label} stops at the first unmet level`, () => {
      const higher = REQUIREMENTS.find((row) => row.strategy === strategy.id && row.minLevel === 2 && row.answerId === row.id);
      const answers = yesAll();
      if (!higher) {
        for (const row of REQUIREMENTS.filter((item) => item.strategy === strategy.id && item.minLevel === 3)) answers[row.id] = "no";
        expect(level(rate(answers), strategy.id).level).toBe(2);
        return;
      }
      answers[higher.answerId] = "no";
      const result = rate(answers);
      expect(level(result, strategy.id).level).toBe(1);
      const gap = result.remediation.find((item) => item.requirementId === higher.id)!;
      expect(gap.priority).toBe(2);
      expect(gap.dueAt).toBe(new Date(AT.getTime() + 45 * DAY).toISOString());
      expect(result.remediation.some((item) => item.strategy === strategy.id && item.priority === 3)).toBe(false);
    });
  }

  it("counts one shared logging answer against each strategy that lists it", () => {
    const answers = yesAll();
    answers["log-protected"] = "no";
    const result = rate(answers);
    for (const id of ["mfa", "restrict_admin", "application_control", "user_app_hardening"] as const) {
      expect(level(result, id).level).toBe(1);
    }
    expect(level(result, "patch_applications").level).toBe(3);
    expect(level(result, "regular_backups").level).toBe(3);
    expect(level(result, "office_macros").level).toBe(3);
  });

  it("follows contradicting evidence and still shows the yes answer", () => {
    const result = rate(yesAll(), [{ requirementId: "pa-online-48h", status: "contradicts", detail: "CVE-2024-0001 open 7 days" }]);
    const line = level(result, "patch_applications").lines.find((row) => row.id === "pa-online-48h")!;
    expect(line.answer).toBe("yes");
    expect(line.met).toBe(false);
    expect(line.evidence.status).toBe("contradicts");
    expect(line.evidence.detail).toContain("CVE-2024-0001");
    expect(level(result, "patch_applications").level).toBe(0);
    expect(level(result, "regular_backups").level).toBe(3);
  });

  it("does not let measured evidence turn a no into a pass", () => {
    const now = AT;
    const bundle = evidenceFromTelemetry({
      ...emptySnap(),
      assets: [{ kind: "application", exposure: "internet" }],
    }, now);
    const answers = yesAll();
    answers["pa-online-48h"] = "no";
    const result = scoreEssentialEight({ answers, evidence: bundle.items, telemetry: bundle.telemetry, assessedAt: now, owner: "Ava Chen", cadenceDays: 90 });
    const line = level(result, "patch_applications").lines.find((row) => row.id === "pa-online-48h")!;
    expect(line.evidence.status).toBe("measured");
    expect(line.answer).toBe("no");
    expect(line.met).toBe(false);
  });

  it("keeps an absent backup answer as the rating", () => {
    const bundle = evidenceFromTelemetry(emptySnap(), AT);
    const line = bundle.items.find((item) => item.requirementId === "bk-restore-tested")!;
    expect(line.status).toBe("absent");
    expect(line.detail).toContain("not connected");
    const result = scoreEssentialEight({ answers: yesAll(), evidence: bundle.items, telemetry: bundle.telemetry, assessedAt: AT, owner: "Ava Chen", cadenceDays: 90 });
    const stored = level(result, "regular_backups").lines.find((row) => row.id === "bk-restore-tested")!;
    expect(stored.met).toBe(true);
    expect(stored.evidence.detail).toContain("not connected");
    expect(level(result, "regular_backups").level).toBe(3);
  });
});

describe("essential eight telemetry", () => {
  it("contradicts the 48 hour online-service window for an old known exploited finding", () => {
    const snap = emptySnap();
    snap.assets.push({ kind: "application", exposure: "internet" });
    snap.vulns.push({ cve: "CVE-2024-1111", cvss: 8, kev: true, firstSeen: new Date(AT.getTime() - 49 * 3_600_000), kind: "application", exposure: "internet" });
    const bundle = evidenceFromTelemetry(snap, AT);
    const hit = bundle.items.find((item) => item.requirementId === "pa-online-48h")!;
    expect(hit.status).toBe("contradicts");
    expect(hit.detail).toContain("CVE-2024-1111");
    expect(hit.detail).toContain("CVSS");
    const fresh = evidenceFromTelemetry({
      ...snap,
      vulns: [{ ...snap.vulns[0]!, firstSeen: new Date(AT.getTime() - 47 * 3_600_000) }],
    }, AT);
    expect(fresh.items.find((item) => item.requirementId === "pa-online-48h")!.status).toBe("measured");
  });

  it("treats CVSS 9 or higher as vendor-critical and leaves a low score inside 48 hours", () => {
    const base = { cve: "CVE-2024-2222", kev: false, firstSeen: new Date(AT.getTime() - 3 * DAY), kind: "saas", exposure: "internet" };
    const high = evidenceFromTelemetry({ ...emptySnap(), assets: [{ kind: "saas", exposure: "internet" }], vulns: [{ ...base, cvss: 9.1 }] }, AT);
    expect(high.items.find((item) => item.requirementId === "pa-online-48h")!.status).toBe("contradicts");
    const low = evidenceFromTelemetry({ ...emptySnap(), assets: [{ kind: "saas", exposure: "internet" }], vulns: [{ ...base, cvss: 7 }] }, AT);
    expect(low.items.find((item) => item.requirementId === "pa-online-48h")!.status).toBe("measured");
    expect(low.items.find((item) => item.requirementId === "pa-online-2w")!.status).toBe("measured");
  });

  it("contradicts the two week non-critical window without touching the 48 hour line", () => {
    const snap: TelemetrySnapshot = {
      ...emptySnap(),
      assets: [{ kind: "cloud_resource", exposure: "internet" }],
      vulns: [{ cve: "CVE-2024-3333", cvss: 5, kev: false, firstSeen: new Date(AT.getTime() - 20 * DAY), kind: "cloud_resource", exposure: "internet" }],
    };
    const bundle = evidenceFromTelemetry(snap, AT);
    expect(bundle.items.find((item) => item.requirementId === "pa-online-48h")!.status).toBe("measured");
    expect(bundle.items.find((item) => item.requirementId === "pa-online-2w")!.status).toBe("contradicts");
  });

  it("counts privileged identities and contradicts internet access when that flag is set", () => {
    const bundle = evidenceFromTelemetry({
      ...emptySnap(),
      identities: [
        { privileged: true, mfa: true, internetAccess: true },
        { privileged: false, mfa: false, internetAccess: null },
      ],
      connectors: ["entra"],
    }, AT);
    expect(bundle.telemetry.restrict_admin).toContain("1 privileged identity of 2");
    const internet = bundle.items.find((item) => item.requirementId === "ra-no-internet")!;
    expect(internet.status).toBe("contradicts");
    expect(internet.detail).toContain("internet access");
    const mfa = bundle.items.find((item) => item.requirementId === "mfa-own-sensitive")!;
    expect(mfa.status).toBe("contradicts");
    expect(mfa.detail).toContain("1 of 2");
  });

  it("reads an Intune macro snapshot and leaves backups unmeasured", () => {
    const bundle = evidenceFromTelemetry({
      ...emptySnap(),
      officeMacros: { disabledWithoutNeed: false, internetBlocked: true },
    }, AT);
    expect(bundle.items.find((item) => item.requirementId === "om-disabled")!.status).toBe("contradicts");
    expect(bundle.items.find((item) => item.requirementId === "om-internet")!.status).toBe("measured");
    expect(bundle.items.find((item) => item.requirementId === "om-antivirus")!.status).toBe("absent");
    expect(bundle.telemetry.regular_backups).toContain("not connected");
  });
});

describe("essential eight report", () => {
  it("puts the disclaimer, the answer, the evidence, the owner and the due date into the PDF", async () => {
    const scored = rate(yesAll(), [{ requirementId: "pa-online-48h", status: "contradicts", detail: "CVE-2024-0001 open 7 days" }]);
    const levels = Object.fromEntries(scored.ratings.map((row) => [row.strategy, row.level])) as Record<StrategyId, Level>;
    const result: AssessmentResult = {
      disclaimer: scored.disclaimer,
      model: scored.model,
      assessedAt: AT.toISOString(),
      cadenceDays: 90,
      nextDue: scored.nextDue.toISOString(),
      owner: "Ava Chen",
      telemetry: Object.fromEntries(scored.ratings.map((row) => [row.strategy, row.telemetry])) as AssessmentResult["telemetry"],
      ratings: scored.ratings,
      remediation: scored.remediation,
      previous: null,
      trend: levelTrend(levels, null),
    };
    const content = buildAssessmentReport("River Clinic", result);
    expect(content.sections.some((section) => section.body?.includes("not an ACSC-endorsed audit"))).toBe(true);
    expect(content.sections.some((section) => section.body?.includes("Answer: yes") && section.body?.includes("CVE-2024-0001"))).toBe(true);
    expect(content.sections.some((section) => section.heading === "Remediation plan" && section.body?.includes("Owner: Ava Chen") && section.body?.includes("2026-09-15"))).toBe(true);
    const pdf = await toPdf("Essential Eight self-assessment", content);
    expect(Buffer.from(pdf.subarray(0, 4)).toString()).toBe("%PDF");
    const plain = pdfPlain(pdf);
    expect(plain).toContain("ACSC-endorsed");
    expect(plain).toContain("Ava Chen");
  });
});
