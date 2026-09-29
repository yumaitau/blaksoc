import { z } from "zod";
import type { ProviderHealth } from "@/lib/providers/types";

export const LIVE_VEEAM = "live Veeam is not called from this build";

const system = z.object({
  name: z.string().min(1).max(120),
  hostname: z.string().min(1).max(120).optional(),
  lastSuccessAt: z.string().nullable().optional(),
  failedJobs: z.number().int().nonnegative().default(0),
  restoreTestedAt: z.string().nullable().optional(),
  immutable: z.boolean().default(false),
  offlineCopy: z.boolean().default(false),
});

export const veeamConfig = z
  .object({
    mode: z.enum(["fixture", "live"]).default("fixture"),
    staleHours: z.number().int().min(1).max(24 * 365).default(24),
    systems: z.array(system).default([]),
  })
  .superRefine((value, ctx) => {
    if (value.mode === "live") ctx.addIssue({ code: "custom", message: LIVE_VEEAM });
  });

export type VeeamConfig = z.infer<typeof veeamConfig>;

export function parseBackupInstant(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("backup time");
  return date;
}

/** A protected system is stale when it has no success inside the threshold. */
export function isStaleBackup(lastSuccessAt: Date | null, staleHours: number, now: Date): boolean {
  if (!lastSuccessAt) return true;
  return now.getTime() - lastSuccessAt.getTime() > staleHours * 3_600_000;
}

/** Fixture mode reports healthy. Live mode fails before any vendor call. */
export function veeamHealth(config: { mode: string }): ProviderHealth {
  if (config.mode === "live") return { ok: false, latencyMs: 0, detail: { mode: "live" }, error: LIVE_VEEAM };
  return { ok: true, latencyMs: 0, detail: { mode: "fixture" } };
}
