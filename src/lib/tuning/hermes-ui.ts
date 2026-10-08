/**
 * How Hermes' actions show in blakSOC's UI. Pure: no database, no React.
 */

/** Queue filter `hermes=`: alerts Hermes closed (even if since reopened), alerts whose pattern it annotated, or either. */
export const HERMES_FILTERS = ["closed", "annotated", "any"] as const;
export type HermesFilter = (typeof HERMES_FILTERS)[number];

export const parseHermesFilter = (v: string | undefined): HermesFilter | undefined => (HERMES_FILTERS as readonly string[]).includes(v ?? "") ? (v as HermesFilter) : undefined;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Queue filter `hermesAction=<tuning action id>`; anything else is ignored. */
export const parseHermesAction = (v: string | undefined): string | undefined => (v && UUID.test(v) ? v.toLowerCase() : undefined);

/**
 * What the queue row says about Hermes' closure of an alert: still `closed` by it, `undone` by an analyst (the
 * whole action), or `reopened` (this alert's status was changed since). Null when Hermes never closed it.
 */
export function hermesClosure(a: { tuningActionId: string | null; status: string; hermesUndoneAt?: Date | null }): "closed" | "reopened" | "undone" | null {
  if (!a.tuningActionId) return null;
  if (a.hermesUndoneAt) return "undone";
  return a.status === "FALSE_POSITIVE" ? "closed" : "reopened";
}

export const HERMES_CLOSURE_LABEL = { closed: "Closed by Hermes", reopened: "Hermes closure reopened", undone: "Hermes closure undone" } as const;

/**
 * The alerts a Hermes action touched, in the queue: its closures, the alerts its noise rule moved to the passive
 * lane, or the pattern it annotated (both lanes). Purged alerts are gone, so a purge has no link.
 */
export const hermesActionHref = (a: { id: string; kind: string }): string | null => (a.kind === "purge" ? null : `/soc/alerts?hermesAction=${encodeURIComponent(a.id)}`);

export const HERMES_KIND_LABEL: Record<string, string> = { annotate: "Added a note", close: "Closed as false positive", noise_rule: "Created a noise rule", purge: "Purged closed alerts" };

/** Last run as one line: "3 executed · 1 refused by guardrails · 40 patterns reviewed". */
export function runOutcome(stats: { executed?: unknown; refused?: unknown; dryRun?: unknown; patternsReviewed?: unknown } | null | undefined): string {
  if (!stats) return "No report yet";
  const n = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : 0);
  const parts = [`${n(stats.executed)} executed`, `${n(stats.refused)} refused by guardrails`];
  if (n(stats.dryRun)) parts.push(`${n(stats.dryRun)} dry run${n(stats.dryRun) === 1 ? "" : "s"}`);
  parts.push(`${n(stats.patternsReviewed)} pattern${n(stats.patternsReviewed) === 1 ? "" : "s"} reviewed`);
  return parts.join(" · ");
}
