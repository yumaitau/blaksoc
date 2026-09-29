import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { assessmentDue, dueReminders } from "@/lib/obligations/clock";
import { NOT_ADVICE, NOT_REVIEWED, draftBody, type Applicability, type DraftFacts } from "@/lib/obligations/model";
import { buildEvidencePack } from "@/lib/obligations/report";
import { toPdf } from "@/lib/reports/export";

const START = new Date("2026-01-01T00:00:00.000Z");
const DAY = 86_400_000;

const facts: DraftFacts = {
  tenantName: "Wattle Health",
  incidentTitle: "Mailbox misuse",
  startedAt: START.toISOString(),
  dueAt: assessmentDue(START).toISOString(),
  applicability: { privacyAct: "yes", healthInformation: "yes", governmentContract: "unsure", soci: "no" },
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
    });
    const bytes = await toPdf("Breach assessment evidence pack", content);
    const text = pdfPlain(bytes);
    expect(Buffer.from(bytes.subarray(0, 4)).toString("latin1")).toBe("%PDF");
    expect(text).toContain("not legal advice");
    expect(text).toContain("Wattle Health IT Admin");
    expect(text).toContain("2026-01-03");
    expect(text).toContain("POL-18");
  });
});
