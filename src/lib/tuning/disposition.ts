import type { RiskFactor } from "@/db/schema";

/**
 * Disposition memory: what analysts decided about earlier alerts from the same rule. Pure; the counts
 * come from dispositionStats (src/lib/services/tuning.ts). Only decided alerts count as evidence, so
 * alerts nobody looked at (including passive ones) never teach the score anything.
 */

/** How far back past decisions are read. */
export const DISPOSITION_WINDOW_DAYS = 90;
/** Most recent alerts read per rule, so a very noisy rule costs the same as a quiet one. */
export const DISPOSITION_SAMPLE_CAP = 2000;
/** Fewer decided alerts than this say nothing about a rule. */
export const MIN_SAMPLES = 5;
/** A rule closed as false positive at least this often is scored down. */
export const FP_SHARE = 0.8;

export type DispositionCounts = {
  falsePositive: number;
  resolved: number;
  /** Escalated by a person (manual escalation or incident link), not by automatic grouping. */
  escalated: number;
  contained: number;
  /** Still open, or escalated only by automatic grouping: no human decision yet. */
  other: number;
};

/** `asset` is the same rule on one host; null when the alert has no resolved asset. */
export type DispositionStats = { rule: DispositionCounts; asset: DispositionCounts | null };

export const EMPTY_COUNTS: DispositionCounts = { falsePositive: 0, resolved: 0, escalated: 0, contained: 0, other: 0 };

export const decidedCount = (c: DispositionCounts) => c.falsePositive + c.resolved + c.escalated + c.contained;

/** Share of decided alerts closed as false positive, or null below MIN_SAMPLES. */
export function falsePositiveShare(c: DispositionCounts): number | null {
  const n = decidedCount(c);
  return n >= MIN_SAMPLES ? c.falsePositive / n : null;
}

const times = (n: number) => (n === 1 ? "once" : `${n} times`);

/**
 * Risk factors from past decisions. The host's own history is used when it has enough decided alerts;
 * otherwise the rule's history across the customer. Escalations always use the whole customer: one real
 * incident anywhere is reason enough to look harder.
 */
export function dispositionFactors(stats: DispositionStats | null): RiskFactor[] {
  if (!stats) return [];
  const out: RiskFactor[] = [];
  const onHost = !!stats.asset && decidedCount(stats.asset) >= MIN_SAMPLES;
  const base = onHost ? stats.asset! : stats.rule;
  const share = falsePositiveShare(base);
  if (share != null && share >= FP_SHARE) {
    out.push({
      key: "disposition_fp",
      label: "Usually a false positive",
      // −10 at 80%, −15 at 100%.
      points: -Math.round(10 + (share - FP_SHARE) * 25),
      evidence: `Closed as false positive ${base.falsePositive} of ${decidedCount(base)} times in ${DISPOSITION_WINDOW_DAYS} days ${onHost ? "on this host" : "across this customer"}`,
    });
  }
  const real = stats.rule.escalated + stats.rule.contained;
  if (real > 0) {
    out.push({
      key: "disposition_escalated",
      label: "Rule has led to real incidents",
      points: real >= 3 ? 10 : 6,
      evidence: `Analysts escalated or contained alerts from this rule ${times(real)} in ${DISPOSITION_WINDOW_DAYS} days`,
    });
  }
  return out;
}
