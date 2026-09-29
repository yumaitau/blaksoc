/** Hours before a sensor with no check-in is treated as silent. */
export const STANDARD_SILENT_HOURS = 24;
export const LOW_SILENT_HOURS = 72;

export type HealthLimits = {
  /** Null means the site profile default applies. */
  silentHours: number | null;
  pollLagMinutes: number;
  dmarcStaleHours: number;
  sigmaStaleHours: number;
};

const DEFAULT_LIMITS: HealthLimits = {
  silentHours: null,
  pollLagMinutes: 60,
  dmarcStaleHours: 48,
  sigmaStaleHours: 26,
};

function positive(value: unknown): number | null {
  return typeof value === "number" && value > 0 ? value : null;
}

/** Missing tenant settings keep the code defaults. A stored silent hour of 0 is unset. */
export function healthOf(settings: { health?: Partial<HealthLimits> } | null | undefined): HealthLimits {
  const health = settings?.health;
  return {
    silentHours: positive(health?.silentHours),
    pollLagMinutes: positive(health?.pollLagMinutes) ?? DEFAULT_LIMITS.pollLagMinutes,
    dmarcStaleHours: positive(health?.dmarcStaleHours) ?? DEFAULT_LIMITS.dmarcStaleHours,
    sigmaStaleHours: positive(health?.sigmaStaleHours) ?? DEFAULT_LIMITS.sigmaStaleHours,
  };
}

/**
 * Site override, then tenant override, then 72h on a low-bandwidth site, else 24h.
 * Zero and negative values are treated as unset.
 */
export function silentHours(input: { profile: string; siteHours: number | null; tenantHours: number | null }): number {
  if (input.siteHours != null && input.siteHours > 0) return input.siteHours;
  if (input.tenantHours != null && input.tenantHours > 0) return input.tenantHours;
  return input.profile === "low" ? LOW_SILENT_HOURS : STANDARD_SILENT_HOURS;
}

/** Null last-seen counts as stale. Equal to the limit is still fresh. */
export function olderThan(last: Date | null, limitMs: number, now: Date): boolean {
  if (!last) return true;
  return now.getTime() - last.getTime() > limitMs;
}

export function isSilent(lastSeen: Date, hours: number, now: Date): boolean {
  return olderThan(lastSeen, hours * 3_600_000, now);
}

/** A missing baseline is the first observation, not a regression. */
export function coverageDropped(previous: number | null, current: number): boolean {
  return previous != null && current < previous;
}
