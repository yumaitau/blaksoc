import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { CLOCK_RULES, assessmentDue, clockDue, dueClockReminder, dueReminders, formatZoned, zonedTime } from "@/lib/obligations/clock";
import {
  CLOCK_INFO, NOT_ADVICE, NOT_LAWYER_REVIEWED, NOT_REVIEWED, clockApplies, clockDraftBody, draftBody, type Applicability, type DraftFacts,
} from "@/lib/obligations/model";
import { buildEvidencePack } from "@/lib/obligations/report";
import { toPdf } from "@/lib/reports/export";

const START = new Date("2026-01-01T00:00:00.000Z");
const DAY = 86_400_000;
const HOUR = 3_600_000;

const facts: DraftFacts = {
  tenantName: "Wattle Health",
  incidentTitle: "Mailbox misuse",
  startedAt: START.toISOString(),
  dueAt: assessmentDue(START).toISOString(),
  applicability: { privacyAct: "yes", healthInformation: "yes", governmentContract: "unsure", soci: "no", ransomwareReporting: "unsure" },
  seriousHarm: "unsure",
  seriousHarmRationale: "We do not know who opened the file.",
  decision: "assessing",
  decisionRationale: "Still checking the mailbox logs.",
  authorName: "Wattle Health IT Admin",
};

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

describe("obligation clock", () => {
  it("ends 30 days after the start time", () => {
    expect(assessmentDue(START).toISOString()).toBe("2026-01-31T00:00:00.000Z");
  });

  it("schedules reminders on days 7, 14, 21, 28 and 30, and skips keys already attempted", () => {
    expect(dueReminders(START, new Date(START.getTime() + 6 * DAY), [])).toEqual([]);
    expect(dueReminders(START, new Date(START.getTime() + 7 * DAY - 1), [])).toEqual([]);
    expect(dueReminders(START, new Date(START.getTime() + 7 * DAY), [])).toEqual(["7"]);
    expect(dueReminders(START, new Date(START.getTime() + 14 * DAY), ["7"])).toEqual(["14"]);
    expect(dueReminders(START, new Date(START.getTime() + 30 * DAY), [])).toEqual(["7", "14", "21", "28", "30"]);
    expect(dueReminders(START, new Date(START.getTime() - DAY), [])).toEqual([]);
  });
});

describe("SOCI and ransomware payment clocks", () => {
  const AWARE = new Date("2026-03-01T22:15:00.000Z");
  const at = (hours: number) => new Date(AWARE.getTime() + hours * HOUR);

  it("ends 12 hours after awareness for a critical incident and 72 hours otherwise", () => {
    expect(clockDue("soci_critical", AWARE).toISOString()).toBe("2026-03-02T10:15:00.000Z");
    expect(clockDue("soci_other", AWARE).toISOString()).toBe("2026-03-04T22:15:00.000Z");
    expect(clockDue("ransomware_payment", AWARE).toISOString()).toBe("2026-03-04T22:15:00.000Z");
  });

  it("reminds before the 12-hour deadline and at it", () => {
    expect(CLOCK_RULES.soci_critical.reminders.every((hour) => hour <= 12)).toBe(true);
    expect(dueClockReminder("soci_critical", AWARE, at(5.99), [])).toBeNull();
    expect(dueClockReminder("soci_critical", AWARE, at(6), [])).toBe("6");
    expect(dueClockReminder("soci_critical", AWARE, at(7), ["6"])).toBeNull();
    expect(dueClockReminder("soci_critical", AWARE, at(9), ["6"])).toBe("9");
    expect(dueClockReminder("soci_critical", AWARE, at(11), ["6", "9"])).toBe("11");
    expect(dueClockReminder("soci_critical", AWARE, at(12), ["6", "9", "11"])).toBe("12");
    expect(dueClockReminder("soci_critical", AWARE, at(30), ["6", "9", "11", "12"])).toBeNull();
    expect(dueClockReminder("soci_critical", AWARE, at(-1), [])).toBeNull();
  });

  it("sends only the latest reminder when a start is back-dated or the worker is late", () => {
    expect(dueClockReminder("soci_critical", AWARE, at(10), [])).toBe("9");
    expect(dueClockReminder("ransomware_payment", AWARE, at(67), [])).toBe("66");
    expect(dueClockReminder("soci_other", AWARE, at(23), [])).toBeNull();
    expect(dueClockReminder("soci_other", AWARE, at(24), [])).toBe("24");
  });

  it("reads the entered wall time in the chosen Australian time zone", () => {
    // AEDT is UTC+11 in March; AWST is UTC+8 all year; Brisbane has no daylight saving.
    expect(zonedTime("2026-03-02T09:15", "Australia/Sydney").toISOString()).toBe(AWARE.toISOString());
    expect(zonedTime("2026-07-01T09:00", "Australia/Sydney").toISOString()).toBe("2026-06-30T23:00:00.000Z");
    expect(zonedTime("2026-03-02T06:15", "Australia/Perth").toISOString()).toBe(AWARE.toISOString());
    expect(zonedTime("2026-01-01T10:00", "Australia/Brisbane").toISOString()).toBe("2026-01-01T00:00:00.000Z");
    expect(zonedTime("2026-01-01T10:00", "UTC").toISOString()).toBe("2026-01-01T10:00:00.000Z");
    // Sydney moves to daylight time at 02:00 on 4 October 2026.
    expect(zonedTime("2026-10-04T01:30", "Australia/Sydney").toISOString()).toBe("2026-10-03T15:30:00.000Z");
    expect(zonedTime("2026-10-04T03:30", "Australia/Sydney").toISOString()).toBe("2026-10-03T16:30:00.000Z");
    expect(Number.isNaN(zonedTime("2026-01-01", "UTC").getTime())).toBe(true);
    expect(Number.isNaN(zonedTime("2026-01-01T10:00", "America/New_York").getTime())).toBe(true);
    expect(formatZoned(AWARE, "Australia/Sydney")).toBe("2026-03-02 09:15 Australia/Sydney");
  });

  it("offers a clock unless the applicability answer rules it out", () => {
    const base: Applicability = { privacyAct: "yes", healthInformation: "no", governmentContract: "no", soci: "no", ransomwareReporting: "no" };
    expect(clockApplies("soci_critical", base)).toBe(false);
    expect(clockApplies("soci_other", { ...base, soci: "unsure" })).toBe(true);
    expect(clockApplies("ransomware_payment", base)).toBe(false);
    expect(clockApplies("ransomware_payment", { ...base, ransomwareReporting: "yes" })).toBe(true);
    expect(clockApplies("ransomware_payment", { ...base, soci: "yes" })).toBe(true);
  });

  it("drafts reports that cite the Act, are not legal advice, and are never sent", () => {
    for (const kind of ["soci_critical", "soci_other", "ransomware_payment"] as const) {
      const body = clockDraftBody(kind, {
        tenantName: "Wattle Health", incidentTitle: "Ransomware", startedAt: "2026-03-02 09:15 Australia/Sydney",
        dueAt: "2026-03-02 21:15 Australia/Sydney", applicability: facts.applicability, authorName: "Wattle Health IT Admin",
      });
      expect(body).toContain(NOT_ADVICE);
      expect(body).toContain(NOT_LAWYER_REVIEWED);
      expect(body).toContain(CLOCK_INFO[kind].act);
      expect(body).toContain("does not submit this report");
      expect(body).toContain("legal adviser");
    }
    expect(CLOCK_INFO.soci_critical.act).toContain("s30BC");
    expect(CLOCK_INFO.soci_other.act).toContain("s30BD");
    expect(CLOCK_INFO.ransomware_payment.act).toContain("Cyber Security Act 2024");
  });
});

describe("obligation drafts", () => {
  it("marks every draft as unsent and not legal advice", () => {
    const applicability: Applicability = facts.applicability;
    expect(applicability.healthInformation).toBe("yes");
    for (const kind of ["oaic", "individuals", "board"] as const) {
      const body = draftBody(kind, facts);
      expect(body).toContain(NOT_ADVICE);
      expect(body).toContain(NOT_REVIEWED);
      expect(body).toContain("has not been sent");
      expect(body.toLowerCase()).not.toContain("we have notified the oaic");
    }
    expect(draftBody("individuals", facts)).toContain("Option B. To read aloud.");
    expect(draftBody("oaic", facts)).toContain("does not submit this form");
  });
});

describe("obligation evidence pack", () => {
  it("puts the author, the time and the disclaimer in the PDF", async () => {
    const content = buildEvidencePack({
      tenantName: "Wattle Health",
      incidentTitle: "Mailbox misuse",
      generatedAt: START.toISOString(),
      startedAt: START.toISOString(),
      dueAt: assessmentDue(START).toISOString(),
      applicability: facts.applicability,
      seriousHarm: "unsure",
      seriousHarmRationale: "We do not know who opened the file.",
      seriousHarmBy: "Wattle Health IT Admin",
      seriousHarmAt: "2026-01-02T00:00:00.000Z",
      decision: "assessing",
      decisionRationale: "Still checking the mailbox logs.",
      decisionBy: "Wattle Health IT Admin",
      decisionAt: "2026-01-03T00:00:00.000Z",
      legalReview: true,
      insurerPolicy: "POL-18",
      referrals: { idcare: { at: "2026-01-04T00:00:00.000Z", byName: "Wattle Health IT Admin" } },
      reminders: [{ key: "7", at: "2026-01-08T00:00:00.000Z", channel: "sms", destination: "+61400000000", status: "sent" }],
      drafts: [{ kind: "board", body: NOT_ADVICE, createdAt: "2026-01-05T00:00:00.000Z", authorName: "Wattle Health IT Admin" }],
      events: [{ at: "2026-01-03T00:00:00.000Z", title: "Decision: assessing", detail: "Wattle Health IT Admin. Still checking the mailbox logs." }],
      clocks: [{
        kind: "soci_critical", startedAt: "2026-01-01 09:00 Australia/Sydney", dueAt: "2026-01-01 21:00 Australia/Sydney", startedBy: "Wattle Health IT Admin",
        reportedAt: "2026-01-01T08:00:00.000Z", reportedBy: "Wattle Health IT Admin", reportRef: "ASD-1234",
        reminders: [{ key: "6", at: "2026-01-01T04:00:00.000Z", channel: "sms", destination: "+61400000000", status: "sent" }],
      }],
    });
    const bytes = await toPdf("Breach assessment evidence pack", content);
    const text = pdfPlain(bytes);
    expect(Buffer.from(bytes.subarray(0, 4)).toString("latin1")).toBe("%PDF");
    expect(text).toContain("not legal advice");
    expect(text).toContain("Wattle Health IT Admin");
    expect(text).toContain("2026-01-03");
    expect(text).toContain("POL-18");
    expect(text).toContain("s30BC");
    expect(text).toContain("ASD-1234");
  });
});
