import type { ClockKind } from "./clock";

export const ANSWERS = ["yes", "no", "unsure"] as const;
export type Answer = (typeof ANSWERS)[number];

export type Applicability = {
  privacyAct: Answer;
  healthInformation: Answer;
  governmentContract: Answer;
  soci: Answer;
  ransomwareReporting: Answer;
};

export const APPLICABILITY_QUESTIONS: { key: keyof Applicability; label: string }[] = [
  { key: "privacyAct", label: "Is this organisation covered by the Privacy Act?" },
  { key: "healthInformation", label: "Does this incident involve health information?" },
  { key: "governmentContract", label: "Does a government contract require extra reporting?" },
  { key: "soci", label: "Is this organisation a responsible entity for a critical infrastructure asset under the Security of Critical Infrastructure Act?" },
  { key: "ransomwareReporting", label: "Is annual turnover over AUD 3 million, or is this organisation a SOCI responsible entity? (Ransomware payment reporting)" },
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
    line("Ransomware payment reporting", facts.applicability.ransomwareReporting),
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

export const NOT_LAWYER_REVIEWED = "A lawyer has not reviewed this wording. Check the reporting duty and the deadline with your legal adviser.";

/** Conservative summaries of the statute. Each one ends by sending the reader to a legal adviser. */
export const CLOCK_INFO: Record<ClockKind, { label: string; started: string; act: string; basis: string; to: string }> = {
  soci_critical: {
    label: "SOCI critical cyber security incident (12 hours)",
    started: "When you became aware of the incident",
    act: "Security of Critical Infrastructure Act 2018, s30BC",
    basis: "As we read s30BC, a responsible entity for a critical infrastructure asset must report a cyber security incident that has had, or is having, a significant impact on the availability of the asset. The report is due as soon as practicable and within 12 hours after the entity becomes aware of the incident. If the report is made orally, a written record is expected within 84 hours after the oral report.",
    to: "the Australian Signals Directorate's Australian Cyber Security Centre (ACSC)",
  },
  soci_other: {
    label: "SOCI other cyber security incident (72 hours)",
    started: "When you became aware of the incident",
    act: "Security of Critical Infrastructure Act 2018, s30BD",
    basis: "As we read s30BD, a responsible entity for a critical infrastructure asset must report a cyber security incident that has had, is having, or is likely to have a relevant impact on the asset. The report is due as soon as practicable and within 72 hours after the entity becomes aware of the incident. If the report is made orally, a written record is expected within 48 hours after the oral report.",
    to: "the Australian Signals Directorate's Australian Cyber Security Centre (ACSC)",
  },
  ransomware_payment: {
    label: "Ransomware payment report (72 hours)",
    started: "When the payment was made, or when you became aware it was made",
    act: "Cyber Security Act 2024, Part 3 (ss 26 and 27)",
    basis: "As we read Part 3, a reporting business entity that makes a ransomware payment, or on whose behalf one is made, must report it within 72 hours after making the payment or becoming aware that it was made. The duty covers businesses above the turnover threshold set in the rules (AUD 3 million at the time of writing) and SOCI responsible entities.",
    to: "the Australian Signals Directorate (ASD)",
  },
};

/** "unsure" still allows the clock: tracking one that turns out not to apply costs less than missing one. */
export function clockApplies(kind: ClockKind, applicability: Applicability): boolean {
  if (kind === "ransomware_payment") return applicability.ransomwareReporting !== "no" || applicability.soci === "yes";
  return applicability.soci !== "no";
}

export type ClockDraftFacts = {
  tenantName: string;
  incidentTitle: string;
  startedAt: string;
  dueAt: string;
  applicability: Applicability;
  authorName: string;
};

/** Draft ACSC SOCI report or ransomware payment report. Headings to fill in, never sent by blakSOC. */
export function clockDraftBody(kind: ClockKind, facts: ClockDraftFacts): string {
  const info = CLOCK_INFO[kind];
  const head = [
    NOT_ADVICE,
    NOT_LAWYER_REVIEWED,
    "",
    `Draft ${info.label} for ${info.to}. blakSOC does not submit this report. A person must check it and submit it through the official channel.`,
    "",
    `Legal basis: ${info.act}. ${info.basis} Check with your legal adviser that this duty applies and that the deadline below is right.`,
    "",
    line("Organisation", facts.tenantName),
    line("Incident", facts.incidentTitle),
    line(info.started, facts.startedAt),
    line("Report due by", facts.dueAt),
    line("SOCI responsible entity", facts.applicability.soci),
    line("Ransomware payment reporting applies", facts.applicability.ransomwareReporting),
    line("Prepared by", facts.authorName),
    "",
  ];
  const fill = "[fill in]";
  const body = kind === "ransomware_payment"
    ? [
      "The headings below follow the content s27 asks for, as we read it. The rules may ask for more. Check the current form.",
      `Contact and business details of the entity reporting: ${fill}`,
      `If another entity made the payment for you, its contact and business details: ${fill}`,
      `The cyber security incident, including its impact on the business: ${fill}`,
      `The demand made by the extorting entity: ${fill}`,
      `The payment (amount, currency or cryptocurrency, method, and when it was made): ${fill}`,
      `Communications with the extorting entity about the incident, the demand and the payment: ${fill}`,
      "",
      "Do not say a payment report has been made until a person has actually submitted it.",
    ]
    : [
      `Critical infrastructure asset affected: ${fill}`,
      `What happened, and how you became aware of it: ${fill}`,
      kind === "soci_critical"
        ? `Significant impact on the availability of the asset: ${fill}`
        : `Relevant impact on the asset (availability, integrity, reliability or confidentiality): ${fill}`,
      `Actions taken so far: ${fill}`,
      `Contact person for the ACSC: ${fill}`,
      "",
      "If you report by phone first, record who you spoke to and when, and send the written record within the time the Act allows.",
    ];
  return [...head, ...body].join("\n");
}
