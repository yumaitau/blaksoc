export const ANSWERS = ["yes", "no", "unsure"] as const;
export type Answer = (typeof ANSWERS)[number];

export type Applicability = {
  privacyAct: Answer;
  healthInformation: Answer;
  governmentContract: Answer;
  soci: Answer;
};

export const APPLICABILITY_QUESTIONS: { key: keyof Applicability; label: string }[] = [
  { key: "privacyAct", label: "Is this organisation covered by the Privacy Act?" },
  { key: "healthInformation", label: "Does this incident involve health information?" },
  { key: "governmentContract", label: "Does a government contract require extra reporting?" },
  { key: "soci", label: "Does the Security of Critical Infrastructure Act apply to this organisation?" },
];

export const DECISIONS = ["assessing", "eligible", "not_eligible"] as const;
export type BreachDecision = (typeof DECISIONS)[number];

export const REFERRALS = ["reportcyber", "idcare", "bank", "police", "insurer"] as const;
export type ReferralKey = (typeof REFERRALS)[number];

export const REFERRAL_LABELS: Record<ReferralKey, string> = {
  reportcyber: "ACSC ReportCyber",
  idcare: "IDCARE for people who are affected",
  bank: "Bank",
  police: "Police",
  insurer: "Cyber insurer",
};

export const DRAFT_KINDS = ["oaic", "individuals", "board"] as const;
export type DraftKind = (typeof DRAFT_KINDS)[number];

export const DRAFT_LABELS: Record<DraftKind, string> = {
  oaic: "OAIC statement",
  individuals: "Note to people affected",
  board: "Board briefing",
};

export const NOT_ADVICE = "This is not legal advice. This draft has not been sent.";
export const NOT_REVIEWED = "The Indigenous advisory group has not reviewed this wording.";

export type DraftFacts = {
  tenantName: string;
  incidentTitle: string;
  startedAt: string;
  dueAt: string;
  applicability: Applicability;
  seriousHarm: string;
  seriousHarmRationale: string;
  decision: string;
  decisionRationale: string;
  authorName: string;
};

function line(label: string, value: string) {
  return `${label}: ${value || "not recorded"}`;
}

export function draftBody(kind: DraftKind, facts: DraftFacts): string {
  const banner = `${NOT_ADVICE}\n${NOT_REVIEWED}`;
  const shared = [
    line("Organisation", facts.tenantName),
    line("Incident", facts.incidentTitle),
    line("Assessment started", facts.startedAt),
    line("Assessment due", facts.dueAt),
    line("Privacy Act coverage", facts.applicability.privacyAct),
    line("Health information", facts.applicability.healthInformation),
    line("Government contract reporting", facts.applicability.governmentContract),
    line("SOCI Act", facts.applicability.soci),
    line("Serious harm", facts.seriousHarm),
    facts.seriousHarmRationale ? `Serious harm note: ${facts.seriousHarmRationale}` : "Serious harm note: not recorded",
    line("Decision", facts.decision),
    facts.decisionRationale ? `Decision note: ${facts.decisionRationale}` : "Decision note: not recorded",
    line("Prepared by", facts.authorName),
  ].join("\n");

  if (kind === "oaic") {
    return [
      banner,
      "",
      "Draft statement for the OAIC Notifiable Data Breaches form. blakSOC does not submit this form.",
      "",
      shared,
      "",
      "Describe what happened in your own words before you use the OAIC form. Say what information was involved and what you have done to limit harm. Recommend that people contact the organisation, and tell them IDCARE can help with identity misuse. Do not say you have notified anyone unless you have actually done that.",
    ].join("\n");
  }
  if (kind === "individuals") {
    return [
      banner,
      "",
      "Option A. Letter.",
      "",
      `We are writing because an incident at ${facts.tenantName} may involve your information.`,
      `The incident is: ${facts.incidentTitle}.`,
      `Health information involved: ${facts.applicability.healthInformation}.`,
      "You can contact the organisation if you have questions. If you are worried about your identity, IDCARE is a free Australian service. We have not contacted IDCARE for you.",
      "We have not decided the legal notification duty in this letter. A lawyer has not signed it.",
      "",
      "Option B. To read aloud.",
      "",
      `We had an incident that may involve your information. It is called: ${facts.incidentTitle}. We are still checking what happened. You can call us. IDCARE can help if you are worried about your identity. This note has not been sent.`,
      "",
      shared,
    ].join("\n");
  }
  return [
    banner,
    "",
    "Board briefing. This is a working note for directors. It is not a notice to the OAIC or to individuals.",
    "",
    shared,
    "",
    "Nothing in this briefing has been filed or posted. The drafts on the incident are still drafts until a person sends them outside blakSOC.",
  ].join("\n");
}
