import { describe, expect, it } from "vitest";
import { isStaleBackup, LIVE_VEEAM, parseBackupInstant, veeamConfig, veeamHealth } from "@/lib/backup/status";
import { connectorDef } from "@/lib/connectors/registry";
import { VeeamProvider } from "@/lib/providers/veeam";

const NOW = new Date("2026-09-01T00:00:00.000Z");
const hours = (n: number) => new Date(NOW.getTime() - n * 3_600_000);

describe("backup assurance", () => {
  it("marks a missing or overdue success as stale and keeps an exact threshold fresh", () => {
    expect(isStaleBackup(null, 48, NOW)).toBe(true);
    expect(isStaleBackup(hours(49), 48, NOW)).toBe(true);
    expect(isStaleBackup(hours(48), 48, NOW)).toBe(false);
    expect(isStaleBackup(hours(47), 48, NOW)).toBe(false);
  });

  it("rejects live Veeam config and reports fixture health without a network call", async () => {
    expect(() => veeamConfig.parse({ mode: "live", staleHours: 24, systems: [] })).toThrow(/live Veeam/);
    expect(veeamConfig.parse({ systems: [{ name: "File" }] })).toMatchObject({ mode: "fixture", staleHours: 24 });
    expect(veeamHealth({ mode: "live" })).toMatchObject({ ok: false, error: LIVE_VEEAM });
    expect(veeamHealth({ mode: "fixture" })).toMatchObject({ ok: true, detail: { mode: "fixture" } });
    const provider = new VeeamProvider({ mode: "live", staleHours: 24, systems: [] });
    await expect(provider.health()).resolves.toMatchObject({ ok: false, error: LIVE_VEEAM });
    expect(parseBackupInstant(null)).toBeNull();
    expect(parseBackupInstant("")).toBeNull();
    expect(parseBackupInstant("2026-09-01T00:00:00.000Z")?.toISOString()).toBe(NOW.toISOString());
    expect(() => parseBackupInstant("not-a-date")).toThrow(/backup time/);
  });

  it("ships Veeam as an available backup connector", () => {
    expect(connectorDef("veeam")).toMatchObject({ status: "available", category: "backup", capabilities: ["assets"] });
  });
});
