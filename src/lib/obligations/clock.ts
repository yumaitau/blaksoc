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

export const HOUR_MS = 3_600_000;

/**
 * Hour-based reporting clocks. SOCI Act 2018 s30BC (critical, 12 hours) and s30BD (other, 72 hours)
 * run from becoming aware of the incident. Cyber Security Act 2024 s27 runs 72 hours from making the
 * ransomware payment or becoming aware it was made. Reminders are hours elapsed; the last is the deadline.
 */
export const CLOCK_KINDS = ["soci_critical", "soci_other", "ransomware_payment"] as const;
export type ClockKind = (typeof CLOCK_KINDS)[number];

export const CLOCK_RULES: Record<ClockKind, { hours: number; reminders: readonly number[] }> = {
  soci_critical: { hours: 12, reminders: [6, 9, 11, 12] },
  soci_other: { hours: 72, reminders: [24, 48, 66, 72] },
  ransomware_payment: { hours: 72, reminders: [24, 48, 66, 72] },
};

export function clockDue(kind: ClockKind, startedAt: Date): Date {
  return new Date(startedAt.getTime() + CLOCK_RULES[kind].hours * HOUR_MS);
}

/**
 * The one reminder to send now, or null. Only the latest threshold reached counts: on a 12-hour clock a
 * late worker or a back-dated start should send "1 hour left", not a stale "6 hours left" first.
 */
export function dueClockReminder(kind: ClockKind, startedAt: Date, now: Date, sent: readonly string[]): string | null {
  const age = now.getTime() - startedAt.getTime();
  const latest = CLOCK_RULES[kind].reminders.filter((hour) => age >= hour * HOUR_MS).at(-1);
  if (latest === undefined || sent.includes(String(latest))) return null;
  return String(latest);
}

export const CLOCK_ZONES = ["Australia/Sydney", "Australia/Brisbane", "Australia/Adelaide", "Australia/Darwin", "Australia/Perth", "UTC"] as const;

function zoneOffset(at: number, timeZone: string): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).formatToParts(new Date(at));
  const get = (type: string) => Number(parts.find((part) => part.type === type)?.value);
  return Date.UTC(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), get("second")) - at;
}

/** A datetime-local value ("2026-03-01T09:30") read as wall time in one of CLOCK_ZONES. Bad input gives an invalid Date. */
export function zonedTime(local: string, timeZone: string): Date {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(local);
  if (!m || !(CLOCK_ZONES as readonly string[]).includes(timeZone)) return new Date(Number.NaN);
  const wall = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]));
  // The second pass corrects the offset when the first guess lands across a daylight-saving change.
  const first = wall - zoneOffset(wall, timeZone);
  return new Date(wall - zoneOffset(first, timeZone));
}

/** "2026-03-01 09:30 Australia/Sydney". */
export function formatZoned(at: Date, timeZone: string): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  }).formatToParts(at);
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? "";
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")} ${timeZone}`;
}
