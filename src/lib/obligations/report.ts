import type { ReportContent } from "@/lib/reports/types";
import type { ClockKind } from "./clock";
import { CLOCK_INFO, NOT_ADVICE, NOT_LAWYER_REVIEWED, NOT_REVIEWED, REFERRAL_LABELS, type Applicability, type ReferralKey } from "./model";

export type PackReminder = { key: string; at: string; channel: string; destination: string; status: string };
export type PackDraft = { kind: string; body: string; createdAt: string; authorName: string };
export type PackMark = { at: string; byName: string; policyNumber?: string };
export type PackEvent = { at: string; title: string; detail: string | null };
export type PackClock = {
  kind: ClockKind;
  startedAt: string;
  dueAt: string;
  startedBy: string;
  reportedAt: string | null;
  reportedBy: string | null;
  reportRef: string | null;
  reminders: PackReminder[];
};

export type EvidencePackInput = {
  tenantName: string;
  incidentTitle: string;
  generatedAt: string;
  startedAt: string;
  dueAt: string;
  applicability: Applicability;
  seriousHarm: string | null;
  seriousHarmRationale: string | null;
  seriousHarmBy: string | null;
  seriousHarmAt: string | null;
  decision: string | null;
  decisionRationale: string | null;
  decisionBy: string | null;
  decisionAt: string | null;
  legalReview: boolean;
  insurerPolicy: string | null;
  referrals: Partial<Record<ReferralKey, PackMark>>;
  reminders: PackReminder[];
  drafts: PackDraft[];
  events: PackEvent[];
  clocks: PackClock[];
};

function clockLine(clock: PackClock) {
  const info = CLOCK_INFO[clock.kind];
  const reported = clock.reportedAt
    ? `Marked reported ${clock.reportedAt.slice(0, 16)} by ${clock.reportedBy ?? "unknown"}.${clock.reportRef ? ` Reference ${clock.reportRef}.` : ""}`
    : "Not marked reported.";
  const reminders = clock.reminders.length
    ? clock.reminders.map((row) => `Hour ${row.key}: ${row.status} by ${row.channel} to ${row.destination} at ${row.at.slice(0, 16)}.`).join("\n")
    : "No reminder attempted.";
  return `${info.label}. ${info.act}.\nStarted ${clock.startedAt} by ${clock.startedBy}. Due ${clock.dueAt}.\n${reported}\n${reminders}`;
}

function markLine(label: string, mark: PackMark | undefined) {
  if (!mark) return `${label}: not marked.`;
  const policy = mark.policyNumber ? ` Policy ${mark.policyNumber}.` : "";
  return `${label}: marked ${mark.at.slice(0, 16)} by ${mark.byName}.${policy}`;
}

export function buildEvidencePack(input: EvidencePackInput): ReportContent {
  const applicability = [
    `Privacy Act: ${input.applicability.privacyAct}.`,
    `Health information: ${input.applicability.healthInformation}.`,
    `Government contract: ${input.applicability.governmentContract}.`,
    `SOCI Act: ${input.applicability.soci}.`,
    `Ransomware payment reporting: ${input.applicability.ransomwareReporting}.`,
  ].join("\n");
  const reminders = input.reminders.length
    ? input.reminders.map((row) => `Day ${row.key}: ${row.status} by ${row.channel} to ${row.destination} at ${row.at.slice(0, 16)}.`).join("\n")
    : "No clock reminder has been attempted.";
  const drafts = input.drafts.length
    ? input.drafts.map((row) => `${row.kind} draft by ${row.authorName} at ${row.createdAt.slice(0, 16)}.\n${row.body}`).join("\n\n")
    : "No drafts saved.";
  const events = input.events.length
    ? input.events.map((row) => `${row.at.slice(0, 16)} ${row.title}. ${row.detail ?? ""}`.trim()).join("\n")
    : "No obligation events on the timeline.";
  const referrals = (Object.keys(REFERRAL_LABELS) as ReferralKey[]).map((key) => markLine(REFERRAL_LABELS[key], input.referrals[key])).join("\n");

  return {
    tenantName: input.tenantName,
    generatedAt: input.generatedAt,
    period: { start: input.startedAt, end: input.dueAt },
    sections: [
      {
        heading: "Disclaimer",
        basis: "interpretation",
        body: `${NOT_ADVICE} ${NOT_REVIEWED} This pack is a record of what was entered in blakSOC. It is not an OAIC notification or a report to the ASD, and it has not been sent to anyone.`,
      },
      {
        heading: "Assessment clock",
        basis: "observed",
        body: `Incident: ${input.incidentTitle}.\nStarted: ${input.startedAt}.\nDue: ${input.dueAt}.\nThe due time is 30 days after the start time recorded here.`,
      },
      { heading: "Applicability", basis: "observed", body: applicability },
      {
        heading: "Serious harm",
        basis: "observed",
        body: input.seriousHarm
          ? `Answer: ${input.seriousHarm}. By ${input.seriousHarmBy ?? "unknown"} at ${input.seriousHarmAt ?? "unknown"}.\n${input.seriousHarmRationale ?? ""}`
          : "Not recorded.",
      },
      {
        heading: "Decision",
        basis: "observed",
        body: input.decision
          ? `Decision: ${input.decision}. By ${input.decisionBy ?? "unknown"} at ${input.decisionAt ?? "unknown"}.\n${input.decisionRationale ?? ""}`
          : "Not recorded.",
      },
      { heading: "Referrals", basis: "observed", body: `${referrals}\nInsurer policy on the case: ${input.insurerPolicy || "not recorded"}.` },
      { heading: "Legal review", basis: "observed", body: input.legalReview ? "Legal review has been requested." : "Legal review has not been requested." },
      { heading: "Clock reminders", basis: "observed", body: reminders },
      {
        heading: "SOCI and ransomware reporting clocks",
        basis: "observed",
        body: input.clocks.length ? `${NOT_LAWYER_REVIEWED}\n\n${input.clocks.map(clockLine).join("\n\n")}` : "No SOCI or ransomware payment clock started.",
      },
      { heading: "Drafts", basis: "observed", body: drafts },
      { heading: "Timeline", basis: "observed", body: events },
    ],
  };
}
