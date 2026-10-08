/**
 * Limits on what a tuning agent (Hermes) may do. Enforced in blakSOC, whatever the caller claims: the
 * agent only proposes, these decide. Pure, so the API and the tests share one definition.
 */
export const GUARDRAILS = {
  /** Alerts of the pattern closed by people (not by the agent) in the look-back. */
  minHumanClosed: 10,
  /** Share of those closed as false positive. */
  minFalsePositiveShare: 0.8,
  lookbackDays: 90,
  /** No escalation, containment or incident link of the pattern this recently. */
  quietDays: 30,
  /** Alerts one close request may touch. */
  maxCloseAlerts: 5000,
  /** Closed alerts stay this long before they may be purged; undo works throughout. */
  undoWindowDays: 7,
  /** Agent-made noise rules per tenant per 7 days. */
  maxRulesPerTenantPerWeek: 10,
  /** Agent closures across the platform per 7 days. */
  maxClosuresPerWeek: 20_000,
  maxRuleDays: 30,
} as const;

/** Only these may be closed by an agent; high and critical always wait for a person. */
export const CLOSABLE_SEVERITIES = ["informational", "low", "medium"] as const;
/** Agent-made noise rules never make anything above this passive. */
export const AGENT_RULE_MAX_SEVERITY = "medium" as const;

export type PatternEvidence = {
  /** Closed (RESOLVED or FALSE_POSITIVE) by people in the look-back. */
  humanClosed: number;
  humanFalsePositive: number;
  /** ESCALATED, CONTAINED or incident-linked in the quiet period. */
  escalatedRecently: number;
};

/** Why the agent may not act on this pattern, or null when every guardrail holds. */
export function guardrailRefusal(e: PatternEvidence): string | null {
  if (e.humanClosed < GUARDRAILS.minHumanClosed) {
    return `Analysts closed ${e.humanClosed} alert(s) of this pattern in ${GUARDRAILS.lookbackDays} days; at least ${GUARDRAILS.minHumanClosed} are needed before automation may act.`;
  }
  const share = e.humanFalsePositive / e.humanClosed;
  if (share < GUARDRAILS.minFalsePositiveShare) {
    return `Only ${Math.round(share * 100)}% of this pattern's closed alerts were false positives; at least ${GUARDRAILS.minFalsePositiveShare * 100}% are needed.`;
  }
  if (e.escalatedRecently > 0) {
    return `This pattern was escalated, contained or linked to an incident in the last ${GUARDRAILS.quietDays} days.`;
  }
  return null;
}
