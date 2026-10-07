import type { CorrelationRule } from "./engine";

/**
 * Built-in correlation rules. Typed definitions in code for now; tenants can switch any of them
 * off (correlation_rule_settings). Bump `version` whenever a rule's logic changes.
 */

const MIN = 60_000;
const HOUR = 60 * MIN;

/** Ported from correlateImpossibleTravel: two consecutive sign-ins from different countries inside two hours, and the account used its mailbox. */
export const IMPOSSIBLE_TRAVEL: CorrelationRule = {
  id: "m365-impossible-travel",
  version: 1,
  title: "Impossible travel followed by mailbox activity",
  description: "Two consecutive sign-ins for one account from different countries inside two hours, where the same account also used its mailbox.",
  severity: "high",
  category: "bec",
  techniques: ["T1078", "T1114.003"],
  stage: "source",
  enabledByDefault: true,
  groupBy: ["user"],
  clause: {
    type: "sequence",
    id: "travel",
    label: "Sign-ins from two countries",
    within: 2 * HOUR,
    strict: true,
    contiguous: true,
    steps: [
      { id: "from", label: "First sign-in", when: [{ label: "sign-in", match: { event_type: "signin" } }] },
      { id: "to", label: "Next sign-in from another country", when: [{ label: "sign-in", match: { event_type: "signin" }, differsFrom: { step: "from", fields: ["country"] } }] },
    ],
  },
  require: [{ id: "mailbox", label: "Mailbox activity by the same account", match: { event_type: "mailbox_activity" } }],
  eventType: "impossible_travel",
};

/** Ported from correlateMfaFatigue: at least three denied MFA prompts, then an approval, inside 60 minutes. */
export const MFA_FATIGUE: CorrelationRule = {
  id: "m365-mfa-fatigue",
  version: 1,
  title: "MFA fatigue (denied prompts, then approval)",
  description: "Three or more denied MFA prompts for one account followed by an approved prompt, all inside 60 minutes.",
  severity: "high",
  category: "bec",
  techniques: ["T1621"],
  stage: "source",
  enabledByDefault: true,
  groupBy: ["user"],
  clause: {
    type: "sequence",
    id: "fatigue",
    label: "Denied prompts then approval",
    within: 60 * MIN,
    steps: [
      { id: "denied", label: "Denied MFA prompts", when: [{ label: "3+ denials", match: { event_type: "mfa_denied" }, count: 3 }] },
      { id: "approved", label: "Approved MFA prompt", when: [{ label: "approval", match: { event_type: "mfa_success" } }] },
    ],
  },
  eventType: "mfa_fatigue",
};

/**
 * Account takeover, by user: credential pressure (push spam, an MFA fatigue alert or a risky sign-in),
 * then access from a new location or device, then mailbox persistence or an OAuth grant.
 * Works on raw sign-in streams and on stored alerts (where impossible travel stands in for the new-location sign-in).
 */
export const ACCOUNT_TAKEOVER: CorrelationRule = {
  id: "account-takeover",
  version: 1,
  title: "Account takeover: credential pressure, new-location access, then persistence",
  description: "MFA push spam or a risky sign-in, then a successful sign-in from a new location or device, then a new inbox rule, mailbox forward or OAuth grant, for one user inside 24 hours.",
  severity: "critical",
  category: "bec",
  techniques: ["T1621", "T1078", "T1114.003", "T1528"],
  stage: "alerts",
  enabledByDefault: true,
  groupBy: ["user"],
  suppressFor: 24 * HOUR,
  clause: {
    type: "sequence",
    id: "ato",
    label: "Account takeover chain",
    within: 24 * HOUR,
    steps: [
      {
        id: "pressure",
        label: "Credential pressure",
        when: [
          { label: "MFA push spam (3+ denied prompts)", match: { event_type: "mfa_denied" }, count: 3 },
          { label: "MFA fatigue alert", match: { event_type: "mfa_fatigue" } },
          { label: "Risky sign-in", match: { event_type: "risky_signin" } },
        ],
      },
      {
        id: "access",
        label: "Access from a new location or device",
        when: [
          { label: "successful sign-in from a new country or device", match: { event_type: "signin", outcome: "success" }, novel: { fields: ["country", "device"] } },
          { label: "impossible travel", match: { event_type: "impossible_travel" } },
        ],
      },
      {
        id: "persistence",
        label: "Mailbox persistence or app consent",
        when: [
          { label: "inbox rule or forwarding", match: { event_type: ["inbox_rule", "mailbox_forward"] } },
          { label: "OAuth grant", match: { event_type: "oauth_consent" } },
        ],
      },
    ],
  },
  eventType: "account_takeover",
};

/** Risk accumulation: many moderate alerts on one user add up even when none is critical alone. */
export const USER_RISK_ACCUMULATION: CorrelationRule = {
  id: "user-risk-accumulation",
  version: 1,
  title: "Risk accumulating on one user",
  description: "The risk scores of alerts for one user add up to 150 or more inside 24 hours.",
  severity: "high",
  category: "correlation",
  techniques: [],
  stage: "alerts",
  enabledByDefault: true,
  groupBy: ["user"],
  clause: { type: "risk", id: "risk", label: "Alert risk for the user", within: 24 * HOUR, threshold: 150 },
  eventType: "risk_accumulation",
};

export const HOST_RISK_ACCUMULATION: CorrelationRule = {
  ...USER_RISK_ACCUMULATION,
  id: "host-risk-accumulation",
  title: "Risk accumulating on one host",
  description: "The risk scores of alerts for one host add up to 150 or more inside 24 hours.",
  groupBy: ["host"],
  clause: { type: "risk", id: "risk", label: "Alert risk for the host", within: 24 * HOUR, threshold: 150 },
};

/** Count with distinct: one source address behind alerts on three or more hosts inside an hour. */
export const SOURCE_FANOUT: CorrelationRule = {
  id: "source-ip-fanout",
  version: 1,
  title: "One source address alerting on several hosts",
  description: "Alerts from one source IP on three or more distinct hosts inside an hour: scanning, spraying or lateral movement.",
  severity: "high",
  category: "correlation",
  techniques: ["T1021", "T1046"],
  stage: "alerts",
  enabledByDefault: true,
  groupBy: ["src_ip"],
  clause: { type: "count", id: "hosts", label: "Hosts alerting for the source", match: { host: { exists: true } }, threshold: 3, within: HOUR, distinct: "host" },
  eventType: "source_fanout",
};

export const BUILTIN_RULES: CorrelationRule[] = [IMPOSSIBLE_TRAVEL, MFA_FATIGUE, ACCOUNT_TAKEOVER, USER_RISK_ACCUMULATION, HOST_RISK_ACCUMULATION, SOURCE_FANOUT];

export function ruleById(id: string): CorrelationRule | undefined {
  return BUILTIN_RULES.find((r) => r.id === id);
}
