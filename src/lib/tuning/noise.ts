import type { NoiseRuleStatus } from "@/db/schema";

/**
 * Noise rules: which alerts go to the passive lane. Pure, so ingest, the "Mark as noise" backfill and
 * the tests all decide a match the same way. A rule only ever stops an alert from demanding attention;
 * nothing here changes an alert's status, closes it or contains anything.
 */

export const DEFAULT_EXPIRY_DAYS = 30;
export const MAX_EXPIRY_DAYS = 180;
export const MIN_EXPIRY_DAYS = 1;
export const MAX_TITLE_PATTERN = 200;

/** Intel verdicts that keep an alert in the active queue whatever a noise rule says. */
export const NOISE_OVERRIDE_VERDICTS = ["malicious", "suspicious"] as const;

export type NoiseScope = {
  source: string;
  ruleId: string;
  assetId: string | null;
  /** Short host name, see shortHost. */
  hostname: string | null;
  titlePattern: string | null;
};

export type NoiseRuleLike = NoiseScope & { status: string; expiresAt: Date; maxSeverity?: string | null };

export type NoiseCandidate = {
  source: string;
  ruleId: string | null;
  assetId: string | null;
  hostname: string | null;
  title: string;
  severity?: string | null;
  intelVerdict?: string | null;
};

const SEVERITY_RANK: Record<string, number> = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** "WS-01.corp.example" → "ws-01". Same normalisation as the asset dedupe key. */
export function shortHost(host: string | null | undefined): string | null {
  const h = host?.trim().toLowerCase().split(".")[0];
  return h ? h : null;
}

/** Expiry for a rule `days` from `now`. Throws RangeError outside 1–180 whole days. */
export function expiryFrom(days: number = DEFAULT_EXPIRY_DAYS, now = new Date()): Date {
  if (!Number.isInteger(days) || days < MIN_EXPIRY_DAYS || days > MAX_EXPIRY_DAYS) {
    throw new RangeError(`Expiry must be ${MIN_EXPIRY_DAYS}–${MAX_EXPIRY_DAYS} days.`);
  }
  return new Date(now.getTime() + days * 86_400_000);
}

/**
 * Case-insensitive glob where `*` matches any run of characters and everything else is literal.
 * No regular expression, so a pattern cannot backtrack.
 */
export function globMatch(pattern: string, text: string): boolean {
  const parts = pattern.toLowerCase().split("*");
  const t = text.toLowerCase();
  if (parts.length === 1) return t === parts[0];
  const head = parts[0]!;
  const tail = parts.at(-1)!;
  if (!t.startsWith(head)) return false;
  let pos = head.length;
  for (const mid of parts.slice(1, -1)) {
    const at = t.indexOf(mid, pos);
    if (at < 0) return false;
    pos = at + mid.length;
  }
  return t.length - pos >= tail.length && t.endsWith(tail);
}

/** Approved and not yet expired. Proposed, rejected and expired rules never match. */
export function isLive(rule: { status: string; expiresAt: Date }, now = new Date()): boolean {
  return rule.status === "active" && rule.expiresAt.getTime() > now.getTime();
}

/** Status as people should read it: an active rule past its expiry is expired. */
export function effectiveStatus(rule: { status: string; expiresAt: Date }, now = new Date()): NoiseRuleStatus {
  if (rule.status === "active" && !isLive(rule, now)) return "expired";
  return rule.status as NoiseRuleStatus;
}

/** Whether `rule` puts `alert` in the passive lane. Host scope fails closed: an unknown host never matches. */
export function ruleMatches(rule: NoiseRuleLike, alert: NoiseCandidate, now = new Date()): boolean {
  if (!isLive(rule, now)) return false;
  if (!alert.ruleId || rule.source !== alert.source || rule.ruleId !== alert.ruleId) return false;
  if (rule.assetId || rule.hostname) {
    const sameHost = rule.assetId && alert.assetId ? rule.assetId === alert.assetId : !!rule.hostname && shortHost(alert.hostname) === rule.hostname;
    if (!sameHost) return false;
  }
  // A severity cap fails closed too: an alert of unknown severity is above any cap.
  if (rule.maxSeverity && !((SEVERITY_RANK[alert.severity ?? ""] ?? 99) <= (SEVERITY_RANK[rule.maxSeverity] ?? -1))) return false;
  return !rule.titlePattern || globMatch(rule.titlePattern, alert.title);
}

/** Threat intel says this alert matters: it stays active even when a rule matches. */
export const overridesNoise = (alert: Pick<NoiseCandidate, "intelVerdict">) => (NOISE_OVERRIDE_VERDICTS as readonly string[]).includes(alert.intelVerdict ?? "");

/** The first live rule matching `alert`, unless threat intel overrides noise handling. */
export function firstMatch<R extends NoiseRuleLike>(rules: readonly R[], alert: NoiseCandidate, now = new Date()): R | null {
  if (overridesNoise(alert)) return null;
  return rules.find((r) => ruleMatches(r, alert, now)) ?? null;
}

/** "rule 5710 from wazuh on ws-01, titles like “*sshd*”". */
export function describeScope(scope: NoiseScope, hostLabel?: string | null): string {
  const host = scope.assetId || scope.hostname ? ` on ${hostLabel ?? scope.hostname ?? "one host"}` : " on every host";
  return `rule ${scope.ruleId} from ${scope.source}${host}${scope.titlePattern ? `, titles like “${scope.titlePattern}”` : ""}`;
}

/** Plain-language reason stored on a passive alert. */
export const passiveReasonFor = (reason: string) => `Known noise: ${reason}`;
