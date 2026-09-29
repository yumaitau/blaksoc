/** Actions a trainee can record. Order is the thing that is scored. */
export const TRAINEE_ACTIONS = ["triage", "escalate", "contain-request", "note", "close", "asset-check", "intel-check"] as const;
export type TraineeAction = (typeof TRAINEE_ACTIONS)[number];

/** L1 permissions a scenario can mark as the competency it exercises. */
export const TRAINING_SKILLS = ["alert:triage", "incident:write", "asset:read", "intel:read", "playbook:read", "response:request"] as const;
export type TrainingSkill = (typeof TRAINING_SKILLS)[number];

/** Exact position matches, then ten points off for each hint. */
export function scoreAttempt(expected: readonly string[], submitted: readonly string[], hintsUsed: number): number {
  if (expected.length === 0) return 0;
  let hit = 0;
  for (let i = 0; i < expected.length; i += 1) {
    if (submitted[i] === expected[i]) hit += 1;
  }
  return Math.max(0, Math.round((hit / expected.length) * 100) - hintsUsed * 10);
}
