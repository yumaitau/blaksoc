import { describe, expect, it } from "vitest";
import { coverageDropped, healthOf, isSilent, LOW_SILENT_HOURS, olderThan, silentHours, STANDARD_SILENT_HOURS } from "@/lib/health/rules";

const now = new Date("2026-06-01T00:00:00.000Z");

describe("telemetry health rules", () => {
  it("prefers a site limit, then the tenant, then the link profile", () => {
    expect(silentHours({ profile: "low", siteHours: 10, tenantHours: 36 })).toBe(10);
    expect(silentHours({ profile: "low", siteHours: 0, tenantHours: 36 })).toBe(36);
    expect(silentHours({ profile: "low", siteHours: null, tenantHours: null })).toBe(LOW_SILENT_HOURS);
    expect(silentHours({ profile: "standard", siteHours: null, tenantHours: null })).toBe(STANDARD_SILENT_HOURS);
    expect(LOW_SILENT_HOURS).toBe(72);
    expect(STANDARD_SILENT_HOURS).toBe(24);
  });

  it("treats a missing baseline as the first reading and a lower count as a drop", () => {
    expect(coverageDropped(null, 4)).toBe(false);
    expect(coverageDropped(5, 4)).toBe(true);
    expect(coverageDropped(5, 5)).toBe(false);
    expect(coverageDropped(5, 6)).toBe(false);
  });

  it("uses code defaults when the tenant has no health policy", () => {
    expect(healthOf(null)).toEqual({ silentHours: null, pollLagMinutes: 60, dmarcStaleHours: 48, sigmaStaleHours: 26 });
    expect(healthOf({ health: { silentHours: 36, pollLagMinutes: 15 } })).toMatchObject({ silentHours: 36, pollLagMinutes: 15, dmarcStaleHours: 48 });
    expect(healthOf({ health: { silentHours: 0 } }).silentHours).toBeNull();
  });

  it("counts a gap past the limit, and a null reading as stale", () => {
    const seen = new Date(now.getTime() - 24 * 3_600_000);
    expect(isSilent(seen, 24, now)).toBe(false);
    expect(isSilent(new Date(seen.getTime() - 1), 24, now)).toBe(true);
    expect(olderThan(null, 60_000, now)).toBe(true);
    expect(olderThan(new Date(now.getTime() - 30_000), 60_000, now)).toBe(false);
  });
});
