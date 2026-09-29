/** 30-day suspected-breach assessment clock. Midnight UTC on the start date the organisation enters. */
export const ASSESSMENT_DAYS = 30;
export const DAY_MS = 86_400_000;

/** Days after the start time when a reminder is due. The last one is the due day. */
export const REMINDER_DAYS = [7, 14, 21, 28, 30] as const;

export function assessmentDue(startedAt: Date): Date {
  return new Date(startedAt.getTime() + ASSESSMENT_DAYS * DAY_MS);
}

/** Reminder keys whose day has arrived and which have not already been attempted. */
export function dueReminders(startedAt: Date, now: Date, sent: readonly string[]): string[] {
  if (now.getTime() < startedAt.getTime()) return [];
  const age = now.getTime() - startedAt.getTime();
  const done = new Set(sent);
  return REMINDER_DAYS.filter((day) => age >= day * DAY_MS && !done.has(String(day))).map(String);
}
