import { and, desc, eq, gte, lte, ne, notInArray, sql } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { alerts, boardBriefs, cveIntel, e8Assessments, incidents, responseActions, vulnerabilities } from "@/db/schema";
import type { BoardLight, ReportContent, ReportImage, ReportLink, ReportSection } from "./types";

export type BoardSpan = "month" | "quarter";

export class BoardBriefError extends Error {
  constructor(readonly code: "preamble" | "image" | "span") {
    super(code);
  }
}

const MAX_IMAGE_BYTES = 80_000;
const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
const JPEG = Buffer.from([0xff, 0xd8, 0xff]);

const STEPS: Record<string, string> = {
  patch_applications: "Update programs",
  patch_os: "Update computers",
  mfa: "Extra sign-in check",
  restrict_admin: "Limit admin use",
  application_control: "Approved programs only",
  office_macros: "Limit document code",
  user_app_hardening: "Lock the browser",
  regular_backups: "Keep backups",
};

const ACTIONS: Record<string, string> = {
  isolate_endpoint: "took a PC off the net",
  unisolate_endpoint: "put a PC back on the net",
  disable_identity: "turned off an account",
  enable_identity: "turned an account back on",
  block_ioc: "blocked a bad address",
  reset_password: "set a new password",
  revoke_sessions: "signed a user out",
};

const CHANGE: Record<string, string> = {
  up: "Better",
  down: "Worse",
  same: "Same",
  first: "First check",
};

export type BoardAssessment = {
  lowest: number;
  rows: { step: string; level: number; change: string }[];
};

export type BoardFacts = {
  light: BoardLight;
  openCritical: number;
  openHigh: number;
  openHealth: number;
  openExploited: number;
  newProblems: number;
  actionPhrases: string[];
  assessment: BoardAssessment | null;
  preamble: string | null;
  links: {
    problems: ReportLink[];
    health: ReportLink | null;
    flaws: ReportLink | null;
    essentialEight: ReportLink;
  };
};

export function boardSpanDays(span: BoardSpan): number {
  return span === "quarter" ? 90 : 30;
}

export function boardPeriodKey(now: Date, span: BoardSpan): string {
  const year = now.getUTCFullYear();
  const month = now.getUTCMonth();
  if (span === "quarter") return `${year}-Q${Math.floor(month / 3) + 1}`;
  return `${year}-${String(month + 1).padStart(2, "0")}`;
}

export function boardLight(input: {
  openCritical: number;
  openHigh: number;
  openHealth: number;
  openExploited: number;
}): BoardLight {
  if (input.openCritical > 0) return "now";
  if (input.openHigh > 0 || input.openHealth > 0 || input.openExploited > 0) return "look";
  return "steady";
}

export function boardActionPhrase(action: string): string {
  return ACTIONS[action] ?? "took one action";
}

/** Flesch-Kincaid grade plus five. That is a reading age in years, not a US grade. */
export function readingAgeYears(text: string): number {
  const sentences = text.split(/[.!?]+/).map((part) => part.trim()).filter((part) => /[A-Za-z0-9]/.test(part));
  const words = text.split(/[^A-Za-z0-9]+/).filter((word) => /[A-Za-z0-9]/.test(word));
  if (!sentences.length || !words.length) return 0;
  const syll = words.reduce((sum, word) => sum + syllables(word), 0);
  const grade = 0.39 * (words.length / sentences.length) + 11.8 * (syll / words.length) - 15.59;
  return grade + 5;
}

export function boardProse(sections: { heading: string; body?: string; scored?: boolean }[]): string {
  return sections.filter((section) => section.scored !== false).map((section) => joinSentence(section.heading, section.body)).join(" ");
}

function joinSentence(heading: string, body?: string): string {
  const head = heading.trim();
  const rest = (body ?? "").trim();
  const titled = /[.!?]$/.test(head) ? head : `${head}.`;
  return rest ? `${titled} ${rest}` : titled;
}

function syllables(word: string): number {
  const raw = word.toLowerCase().replace(/[^a-z]/g, "");
  if (!raw) return 1;
  if (raw.length <= 3) return 1;
  const trimmed = raw.replace(/(?:[^aeiouy]e|ed|es)$/, "");
  const groups = trimmed.match(/[aeiouy]+/g);
  return Math.max(1, groups?.length ?? 1);
}

export function cleanPreamble(value: string | null): string | null {
  if (value == null) return null;
  const text = value.replace(/\r\n/g, "\n").trim();
  if (!text) return null;
  if (text.length > 600) throw new BoardBriefError("preamble");
  if (/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(text)) throw new BoardBriefError("preamble");
  return text;
}

export function parseBoardImage(mime: string, data: string): ReportImage {
  const raw = data.replace(/\s/g, "");
  if (!/^[A-Za-z0-9+/]+=*$/.test(raw)) throw new BoardBriefError("image");
  const buf = Buffer.from(raw, "base64");
  if (buf.length < 8 || buf.length > MAX_IMAGE_BYTES) throw new BoardBriefError("image");
  if (mime === "image/png" && buf.subarray(0, 4).equals(PNG)) return { mime, data: raw };
  if (mime === "image/jpeg" && buf.subarray(0, 3).equals(JPEG)) return { mime, data: raw };
  throw new BoardBriefError("image");
}

function countSentence(n: number, zero: string, one: string, many: (n: number) => string): string {
  if (n === 0) return zero;
  if (n === 1) return one;
  return many(n);
}

export function boardSections(facts: BoardFacts): ReportSection[] {
  const status = {
    steady: "Steady. Nothing open needs the board today.",
    look: "Needs a look. Something open should be known by the board.",
    now: "Needs attention now. A serious problem is still open.",
  }[facts.light];
  const watch = facts.openExploited > 0
    ? countSentence(facts.openExploited, "", "One flaw that attackers use is still open.", (n) => `${n} flaws that attackers use are still open.`)
    : countSentence(facts.openHealth, "No health warning is open.", "One health warning is open.", (n) => `${n} health warnings are open.`);
  const points = [
    facts.light === "steady" ? "The status is steady." : facts.light === "look" ? "The status needs a look." : "The status needs attention now.",
    countSentence(facts.newProblems, "No new problem opened.", "One new problem opened.", (n) => `${n} new problems opened.`),
    countSentence(facts.actionPhrases.length, "We finished no action.", "We finished one action.", (n) => `We finished ${n} actions.`),
    watch,
    facts.assessment
      ? "Essential Eight means eight basic steps. A check is on file."
      : "Essential Eight means eight basic steps. No check is on file.",
  ];
  const decisions: string[] = [];
  if (facts.openCritical > 0) decisions.push("The board should decide if the serious problem stays open.");
  if (facts.openHigh > 0) decisions.push("The board should name who owns the high problem.");
  if (facts.openExploited > 0) decisions.push("The board should set a date to fix the open flaw.");
  if (!facts.assessment) decisions.push("The board should name who will answer the Essential Eight questions.");
  if (!decisions.length) decisions.push("The board has no decision waiting.");
  const did = facts.actionPhrases.length
    ? `${countSentence(facts.actionPhrases.length, "", "We finished one action.", (n) => `We finished ${n} actions.`)} ${facts.actionPhrases.slice(0, 5).map((phrase) => `We ${phrase}.`).join(" ")}${facts.actionPhrases.length > 5 ? " More actions were finished too." : ""}`
    : "No action was finished in this time.";

  const sections: ReportSection[] = [];
  if (facts.preamble) {
    sections.push({ heading: "Note from your group", basis: "interpretation", author: "analyst", body: facts.preamble, scored: false });
  }
  const watchLinks = [facts.links.health, facts.links.flaws].filter((link): link is ReportLink => link != null);
  sections.push({
    heading: "Overall status",
    basis: "observed",
    body: `${status} Open serious problems: ${facts.openCritical}. Open high problems: ${facts.openHigh}. Open health warnings: ${facts.openHealth}. Open flaws attackers use: ${facts.openExploited}.`,
    links: watchLinks.length ? watchLinks : undefined,
  });
  sections.push({ heading: "Key points", basis: "observed", body: points.join(" ") });
  sections.push({
    heading: "What happened",
    basis: "observed",
    body: countSentence(facts.newProblems, "No new problem opened in this time.", "One new problem opened in this time.", (n) => `${n} new problems opened in this time.`),
    links: facts.links.problems.length ? facts.links.problems : undefined,
  });
  sections.push({ heading: "What we did", basis: "observed", body: did });
  sections.push({ heading: "Decisions for the board", basis: "interpretation", author: "system", body: decisions.join(" ") });
  sections.push({
    heading: "Essential Eight progress",
    basis: "observed",
    body: facts.assessment
      ? `Essential Eight means eight basic steps that make attacks harder. A check is on file. The lowest level is ${facts.assessment.lowest} of 3.`
      : "Essential Eight means eight basic steps that make attacks harder. No check is on file.",
    table: facts.assessment?.rows.length
      ? { columns: ["Step", "Level", "Change"], rows: facts.assessment.rows.map((row) => [row.step, row.level, row.change]) }
      : undefined,
    links: [facts.links.essentialEight],
  });
  sections.push({
    heading: "Words we use",
    basis: "interpretation",
    author: "system",
    body: "An incident is a problem we handle. Essential Eight means eight basic steps that make attacks harder. A level is a score from 0 to 3. Level 0 means step one is not met. This check is your own. It is not an official audit. A health warning means a check went quiet. A flaw is a weak spot in a program. A macro is code inside a document.",
  });
  return sections;
}

function num(value: unknown): number {
  const n = Number(value ?? 0);
  return Number.isFinite(n) ? n : 0;
}

export async function buildBoardContent(
  tx: Tx,
  tenant: { id: string; name: string },
  opts: { start: Date; end: Date; span: BoardSpan },
): Promise<ReportContent> {
  const tenantId = tenant.id;
  const [open] = await tx
    .select({
      critical: sql<number>`count(*) filter (where ${incidents.severity} = 'critical')::int`,
      high: sql<number>`count(*) filter (where ${incidents.severity} = 'high')::int`,
    })
    .from(incidents)
    .where(and(eq(incidents.tenantId, tenantId), ne(incidents.status, "CLOSED")));
  const [fresh] = await tx
    .select({ n: sql<number>`count(*)::int` })
    .from(incidents)
    .where(and(eq(incidents.tenantId, tenantId), gte(incidents.createdAt, opts.start), lte(incidents.createdAt, opts.end)));
  const problemRows = await tx
    .select({ id: incidents.id, ref: incidents.ref })
    .from(incidents)
    .where(and(eq(incidents.tenantId, tenantId), ne(incidents.status, "CLOSED")))
    .limit(5);
  const [health] = await tx
    .select({ n: sql<number>`count(*)::int` })
    .from(alerts)
    .where(and(eq(alerts.tenantId, tenantId), eq(alerts.source, "health"), notInArray(alerts.status, ["RESOLVED", "FALSE_POSITIVE"])));
  const [flaws] = await tx
    .select({ n: sql<number>`count(distinct ${vulnerabilities.cve})::int` })
    .from(vulnerabilities)
    .innerJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve))
    .where(and(eq(vulnerabilities.tenantId, tenantId), eq(vulnerabilities.status, "open"), eq(cveIntel.kev, true)));
  const acts = await tx
    .select({ action: responseActions.action })
    .from(responseActions)
    .where(and(eq(responseActions.tenantId, tenantId), eq(responseActions.status, "SUCCEEDED"), gte(responseActions.createdAt, opts.start), lte(responseActions.createdAt, opts.end)));
  const [assessment] = await tx.select().from(e8Assessments).where(eq(e8Assessments.tenantId, tenantId)).orderBy(desc(e8Assessments.assessedAt)).limit(1);
  const [brief] = await tx.select().from(boardBriefs).where(eq(boardBriefs.tenantId, tenantId));

  const openCritical = num(open?.critical);
  const openHigh = num(open?.high);
  const openHealth = num(health?.n);
  const openExploited = num(flaws?.n);
  const ratings = assessment?.result.ratings ?? [];
  const mapped = ratings.flatMap((row) => {
    const step = STEPS[row.strategy];
    if (!step) return [];
    const level = Number(row.level);
    const trend = assessment?.result.trend?.[row.strategy] ?? "";
    return [{ step, level: Number.isFinite(level) ? level : 0, change: CHANGE[trend] ?? "First check" }];
  });
  const stored: BoardAssessment | null = assessment && mapped.length
    ? { lowest: Math.min(...mapped.map((row) => row.level)), rows: mapped }
    : null;
  const image: ReportImage | null = brief?.imageData && (brief.imageMime === "image/png" || brief.imageMime === "image/jpeg")
    ? { mime: brief.imageMime, data: brief.imageData }
    : null;

  const facts: BoardFacts = {
    light: boardLight({ openCritical, openHigh, openHealth, openExploited }),
    openCritical,
    openHigh,
    openHealth,
    openExploited,
    newProblems: num(fresh?.n),
    actionPhrases: acts.map((row) => boardActionPhrase(row.action)),
    assessment: stored,
    preamble: brief?.preamble ?? null,
    links: {
      problems: problemRows.map((row) => ({ label: `Problem ${row.ref}`, href: `/soc/incidents/${row.id}` })),
      health: openHealth > 0 ? { label: "Health warnings", href: "/soc/alerts" } : null,
      flaws: openExploited > 0 ? { label: "Open flaws", href: "/vulnerabilities" } : null,
      essentialEight: { label: "Essential Eight check", href: "/portal/essential-eight" },
    },
  };

  return {
    tenantName: tenant.name,
    generatedAt: new Date().toISOString(),
    period: { start: opts.start.toISOString(), end: opts.end.toISOString() },
    sections: boardSections(facts),
    audience: "board",
    light: facts.light,
    image,
  };
}
