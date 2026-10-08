import { connectorDef } from "@/lib/connectors/registry";
import type { Severity } from "@/lib/providers/types";

/** Lowest first. */
export const ALERT_FLOOR_SEVERITIES = ["informational", "low", "medium", "high", "critical"] as const satisfies readonly Severity[];

export const SEVERITY_RANK: Record<Severity, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Lowest severity stored per provider unless the integration's `minSeverity` says otherwise. Wazuh's
 * informational events (session opened, sudo, login success) were 95% of the volume and feed no detection;
 * they stay searchable in Wazuh for its retention period.
 */
const DEFAULT_MIN_SEVERITY: Partial<Record<string, Severity>> = { wazuh: "low" };

/** The alert floor in force for an integration: alerts below it are dropped at ingest and stay in the source. */
export function minSeverityFor(row: { provider: string; config: unknown }): Severity {
  const configured = (row.config as { minSeverity?: unknown } | null)?.minSeverity;
  if (typeof configured === "string" && configured in SEVERITY_RANK) return configured as Severity;
  return DEFAULT_MIN_SEVERITY[row.provider] ?? "informational";
}

/** True when the connector's settings carry `minSeverity`, so a floor set from the UI is kept rather than stripped. */
export function supportsAlertFloor(provider: string): boolean {
  const def = connectorDef(provider);
  if (!def?.capabilities.includes("events")) return false;
  const shape = (def.config as { shape?: Record<string, unknown> }).shape;
  return !!shape && "minSeverity" in shape;
}
