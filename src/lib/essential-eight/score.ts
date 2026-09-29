import { DISCLAIMER, MODEL_NOTE, REQUIREMENTS, STRATEGIES, type StrategyId } from "./requirements";

export type Level = 0 | 1 | 2 | 3;
export type Trend = "up" | "down" | "same" | "first";
export type EvidenceStatus = "contradicts" | "absent" | "measured";

export type EvidenceItem = {
  requirementId: string;
  status: EvidenceStatus;
  detail: string;
};

export type RequirementLine = {
  id: string;
  answerId: string;
  strategy: StrategyId;
  minLevel: 1 | 2 | 3;
  text: string;
  answer: "yes" | "no" | "unanswered";
  met: boolean;
  evidence: { status: EvidenceStatus; detail: string };
};

export type StrategyRating = {
  strategy: StrategyId;
  label: string;
  level: Level;
  telemetry: string;
  lines: RequirementLine[];
};

export type RemediationItem = {
  requirementId: string;
  strategy: StrategyId;
  title: string;
  owner: string;
  dueAt: string;
  priority: number;
};

export type ScoreResult = {
  disclaimer: string;
  model: string;
  nextDue: Date;
  ratings: StrategyRating[];
  remediation: RemediationItem[];
};

export type AssessmentResult = {
  disclaimer: string;
  model: string;
  assessedAt: string;
  cadenceDays: number;
  nextDue: string;
  owner: string;
  telemetry: Record<StrategyId, string>;
  ratings: StrategyRating[];
  remediation: RemediationItem[];
  previous: { assessedAt: string; levels: Record<StrategyId, Level> } | null;
  trend: Record<StrategyId, Trend>;
};

const DUE_DAYS: Record<1 | 2 | 3, number> = { 1: 14, 2: 45, 3: 90 };
const DAY_MS = 86_400_000;
const NO_TELEMETRY = "No telemetry for this requirement. The answer stands.";

const strategyOrder = new Map(STRATEGIES.map((row, index) => [row.id, index]));

export function levelsOf(ratings: StrategyRating[]): Record<StrategyId, Level> {
  return Object.fromEntries(ratings.map((row) => [row.strategy, row.level])) as Record<StrategyId, Level>;
}

export function levelTrend(current: Record<StrategyId, Level>, previous: Record<StrategyId, Level> | null): Record<StrategyId, Trend> {
  const out = {} as Record<StrategyId, Trend>;
  for (const strategy of STRATEGIES) {
    if (!previous) out[strategy.id] = "first";
    else if (current[strategy.id] > previous[strategy.id]) out[strategy.id] = "up";
    else if (current[strategy.id] < previous[strategy.id]) out[strategy.id] = "down";
    else out[strategy.id] = "same";
  }
  return out;
}

/**
 * Indicative maturity. A level is met only when every requirement at that level
 * and below is met. A yes contradicted by evidence is not met. Evidence never
 * turns a no into a yes. Board due dates are 14, 45 and 90 days by level.
 */
export function scoreEssentialEight(input: {
  answers: Record<string, "yes" | "no" | undefined>;
  evidence?: EvidenceItem[];
  telemetry?: Partial<Record<StrategyId, string>>;
  assessedAt: Date;
  owner: string;
  cadenceDays: number;
}): ScoreResult {
  const evidenceById = new Map<string, EvidenceItem>();
  for (const item of input.evidence ?? []) evidenceById.set(item.requirementId, item);
  const ratings: StrategyRating[] = [];
  const remediation: RemediationItem[] = [];

  for (const strategy of STRATEGIES) {
    const lines: RequirementLine[] = REQUIREMENTS.filter((row) => row.strategy === strategy.id).map((row) => {
      const raw = input.answers[row.id] ?? input.answers[row.answerId];
      const answer = raw === "yes" || raw === "no" ? raw : "unanswered";
      const item = evidenceById.get(row.id);
      const evidence = item
        ? { status: item.status, detail: item.detail }
        : { status: "absent" as const, detail: NO_TELEMETRY };
      return {
        id: row.id,
        answerId: row.answerId,
        strategy: strategy.id,
        minLevel: row.minLevel,
        text: row.text,
        answer,
        met: answer === "yes" && evidence.status !== "contradicts",
        evidence,
      };
    });
    let level: Level = 0;
    let blocking: 1 | 2 | 3 | null = null;
    for (const step of [1, 2, 3] as const) {
      if (lines.filter((line) => line.minLevel <= step).every((line) => line.met)) level = step;
      else {
        blocking = step;
        break;
      }
    }
    ratings.push({
      strategy: strategy.id,
      label: strategy.label,
      level,
      telemetry: input.telemetry?.[strategy.id] ?? "No telemetry supplied.",
      lines,
    });
    if (blocking) {
      for (const line of lines) {
        if (line.minLevel <= blocking && !line.met) {
          remediation.push({
            requirementId: line.id,
            strategy: strategy.id,
            title: `${strategy.label}: ${line.text}`,
            owner: input.owner,
            dueAt: new Date(input.assessedAt.getTime() + DUE_DAYS[line.minLevel] * DAY_MS).toISOString(),
            priority: line.minLevel,
          });
        }
      }
    }
  }

  remediation.sort((a, b) => a.priority - b.priority || (strategyOrder.get(a.strategy)! - strategyOrder.get(b.strategy)!) || a.requirementId.localeCompare(b.requirementId));
  return {
    disclaimer: DISCLAIMER,
    model: MODEL_NOTE,
    nextDue: new Date(input.assessedAt.getTime() + input.cadenceDays * DAY_MS),
    ratings,
    remediation,
  };
}
