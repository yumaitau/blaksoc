import { inflateSync } from "node:zlib";
import { PDFDocument } from "pdf-lib";
import { describe, expect, it } from "vitest";
import { boardLight, boardPeriodKey, boardProse, boardSections, boardSpanDays, parseBoardImage, readingAgeYears, BoardBriefError, type BoardFacts } from "@/lib/reports/board";
import { toPdf } from "@/lib/reports/export";
import type { ReportContent } from "@/lib/reports/types";

const PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

function facts(patch: Partial<BoardFacts> = {}): BoardFacts {
  return {
    light: "steady",
    openCritical: 0,
    openHigh: 0,
    openHealth: 0,
    openExploited: 0,
    newProblems: 0,
    actionPhrases: [],
    exercises: 0,
    awareness: { sends: 0, clicks: 0 },
    assessment: null,
    preamble: null,
    links: {
      problems: [],
      health: null,
      flaws: null,
      essentialEight: { label: "Essential Eight check", href: "/portal/essential-eight" },
    },
    ...patch,
  };
}

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

describe("board summary prose", () => {
  it("uses a higher reading age for longer words", () => {
    const easy = readingAgeYears("Cats sit. Dogs run.");
    const hard = readingAgeYears("Organisational vulnerability assessments require comprehensive authentication.");
    expect(hard).toBeGreaterThan(easy);
    expect(easy).toBeLessThanOrEqual(12);
  });

  it("keeps generated board text at a reading age of 12 years or under", () => {
    const sections = boardSections(facts({
      light: "now",
      openCritical: 1,
      openHigh: 2,
      openHealth: 3,
      openExploited: 1,
      newProblems: 4,
      actionPhrases: ["took a PC off the net", "turned off an account"],
      assessment: { lowest: 0, rows: [{ step: "Update programs", level: 0, change: "First check" }] },
      preamble: "Organisational cybersecurity transformation leverages synergistic paradigms across the enterprise.",
      links: {
        problems: [{ label: "Problem 9", href: "/soc/incidents/abc" }],
        health: { label: "Health warnings", href: "/soc/alerts" },
        flaws: { label: "Open flaws", href: "/vulnerabilities" },
        essentialEight: { label: "Essential Eight check", href: "/portal/essential-eight" },
      },
    }));
    expect(readingAgeYears(boardProse(sections))).toBeLessThanOrEqual(12);
    expect(sections.map((section) => section.heading)).toEqual([
      "Note from your group",
      "Overall status",
      "Key points",
      "What happened",
      "What we did",
      "Practice",
      "Awareness",
      "Decisions for the board",
      "Essential Eight progress",
      "Words we use",
    ]);
    expect(sections.some((section) => /transparency/i.test(`${section.heading} ${section.body ?? ""}`))).toBe(false);
    expect(sections.find((section) => section.heading === "Note from your group")?.scored).toBe(false);
    expect(sections.find((section) => section.heading === "What happened")?.links?.[0]?.href).toBe("/soc/incidents/abc");
    expect(sections.find((section) => section.heading === "Overall status")?.body).toContain("Open serious problems: 1");
    expect(sections.find((section) => section.heading === "What we did")?.body).toContain("took a PC off the net");
    expect(sections.find((section) => section.heading === "Essential Eight progress")?.body).toContain("lowest level is 0 of 3");
  });

  it("turns open records into a traffic light", () => {
    expect(boardLight({ openCritical: 0, openHigh: 0, openHealth: 0, openExploited: 0 })).toBe("steady");
    expect(boardLight({ openCritical: 0, openHigh: 1, openHealth: 0, openExploited: 0 })).toBe("look");
    expect(boardLight({ openCritical: 0, openHigh: 0, openHealth: 2, openExploited: 0 })).toBe("look");
    expect(boardLight({ openCritical: 0, openHigh: 0, openHealth: 0, openExploited: 1 })).toBe("look");
    expect(boardLight({ openCritical: 1, openHigh: 4, openHealth: 4, openExploited: 4 })).toBe("now");
  });

  it("accepts a real PNG and rejects a mismatched file", () => {
    expect(parseBoardImage("image/png", PNG).mime).toBe("image/png");
    expect(() => parseBoardImage("image/jpeg", PNG)).toThrow(BoardBriefError);
    expect(boardSpanDays("month")).toBe(30);
    expect(boardSpanDays("quarter")).toBe(90);
    expect(boardPeriodKey(new Date("2026-06-15T00:00:00.000Z"), "month")).toBe("2026-06");
    expect(boardPeriodKey(new Date("2026-06-15T00:00:00.000Z"), "quarter")).toBe("2026-Q2");
  });

  it("prints an A4 page and a landscape slide with the status word", async () => {
    const sections = boardSections(facts());
    const content: ReportContent = {
      tenantName: "River Clinic",
      generatedAt: "2026-06-01T00:00:00.000Z",
      period: { start: "2026-05-02T00:00:00.000Z", end: "2026-06-01T00:00:00.000Z" },
      sections,
      audience: "board",
      light: "steady",
      image: { mime: "image/png", data: PNG },
    };
    const page = await PDFDocument.load(await toPdf("Board summary: River Clinic", content));
    const slide = await PDFDocument.load(await toPdf("Board summary: River Clinic", content, "slides"));
    expect(page.getPage(0).getWidth()).toBeLessThan(page.getPage(0).getHeight());
    expect(slide.getPage(0).getWidth()).toBeGreaterThan(slide.getPage(0).getHeight());
    expect(slide.getPageCount()).toBeGreaterThan(sections.length);
    expect(pdfPlain(await toPdf("Board summary: River Clinic", content))).toContain("STEADY");
    const plain = await toPdf("Weekly SOC report", { ...content, audience: undefined, light: undefined, image: null });
    expect(pdfPlain(plain)).toContain("OBSERVED");
    expect(pdfPlain(plain)).not.toContain("STEADY");
  });
});
