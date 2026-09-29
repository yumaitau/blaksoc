import { describe, expect, it } from "vitest";
import { agentGroup, openDownload, PLATFORMS, renderInstaller, signDownload } from "@/lib/agents/download";
import { dailyUploadBytes, PROFILES } from "@/lib/agents/profile";

const KEY = "test-key";

describe("agent kits", () => {
  it("accepts a signed download and rejects tamper or expiry", () => {
    const now = Date.parse("2026-04-01T00:00:00.000Z");
    const token = signDownload({ enrolmentId: "11111111-1111-1111-1111-111111111111", platform: "win-msi", exp: now + 60_000 }, KEY);
    expect(openDownload(token, KEY, now)?.platform).toBe("win-msi");
    expect(openDownload(token, KEY, now + 60_000)).toBeNull();
    expect(openDownload(`${token}x`, KEY, now)).toBeNull();
    expect(openDownload(token, "other-key", now)).toBeNull();
  });

  it("counts the slow profile under 20 MB a day and follows the schedule", () => {
    const low = dailyUploadBytes(PROFILES.low);
    const standard = dailyUploadBytes(PROFILES.standard);
    expect(low).toBeLessThan(20 * 1024 * 1024);
    expect(standard).toBeGreaterThan(low);
    expect(dailyUploadBytes({ ...PROFILES.low, syscollectorSeconds: 3_600 })).toBeGreaterThan(low);
  });

  it("writes the group, token, and profile into each installer", () => {
    for (const platform of PLATFORMS) {
      const file = renderInstaller(platform, {
        manager: "wazuh.example",
        group: agentGroup("River Clinic"),
        token: "enrol-token",
        profile: PROFILES.low,
      });
      expect(file.body).toContain("enrol-token");
      expect(file.body).toContain("riverclinic");
      expect(file.body).toContain("<events_per_second>5</events_per_second>");
      expect(file.body).toContain("<realtime>no</realtime>");
      expect(file.body).toContain("wazuh.example");
    }
  });
});
