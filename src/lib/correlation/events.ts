import type { NormalisedAlert } from "@/lib/providers/types";
import type { CorrelationEvent, CorrelationFinding, CorrelationRule } from "./engine";

/** Source key for alerts the correlation engine raises. */
export const CORRELATION_SOURCE = "blaksoc-correlation";

/** Provider rule ids that mean the same thing as a canonical event type. */
const EVENT_ALIASES: Record<string, string> = {
  "google.login.suspicious": "risky_signin",
  "google.token.oauth": "oauth_consent",
};

export type AlertForCorrelation = {
  id: string;
  source: string;
  ruleId: string | null;
  title: string;
  category: string | null;
  severity: string;
  riskScore: number;
  userName: string | null;
  assetId: string | null;
  hostname: string | null;
  attackTechniques: string[];
  raw: unknown;
  occurredAt: Date;
};

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function pick(raw: Record<string, unknown>, paths: string[]): string | undefined {
  for (const p of paths) {
    let cur: unknown = raw;
    for (const part of p.split(".")) cur = cur && typeof cur === "object" ? (cur as Record<string, unknown>)[part] : undefined;
    const v = str(cur);
    if (v) return v;
  }
  return undefined;
}

/** Raw paths eventFromAlert reads. Loaders fetch only these, never whole provider payloads. */
export const EVENT_RAW_PATHS = [
  "eventType", "agent.name", "hostname", "srcIp", "src_ip", "data.srcip", "ipAddress", "ip",
  "country", "location.countryOrRegion", "deviceId", "deviceDetail.deviceId", "device", "outcome",
] as const;

/** A stored alert as a correlation event. Field names follow the canonical set the rules use. */
export function eventFromAlert(a: AlertForCorrelation): CorrelationEvent {
  const raw = a.raw && typeof a.raw === "object" ? (a.raw as Record<string, unknown>) : {};
  const eventType = str(raw.eventType) ?? (a.ruleId ? EVENT_ALIASES[a.ruleId] : undefined) ?? a.ruleId ?? a.category ?? "alert";
  const fields: Record<string, unknown> = {
    event_type: eventType,
    summary: a.title,
    title: a.title,
    source: a.source,
    rule_id: a.ruleId,
    category: a.category,
    severity: a.severity,
    risk_score: a.riskScore,
    techniques: a.attackTechniques,
    user: a.userName?.toLowerCase() ?? undefined,
    host: (a.hostname ?? pick(raw, ["agent.name", "hostname"]))?.toLowerCase(),
    asset: a.assetId ?? undefined,
    src_ip: pick(raw, ["srcIp", "src_ip", "data.srcip", "ipAddress", "ip"]),
    country: pick(raw, ["country", "location.countryOrRegion"]),
    device: pick(raw, ["deviceId", "deviceDetail.deviceId", "device"]),
    outcome: pick(raw, ["outcome"]),
  };
  return { id: a.id, at: a.occurredAt.getTime(), fields };
}

/** The alert a finding raises. External id is the dedupe key, so re-ingesting it is a no-op. */
export function alertFromFinding(rule: CorrelationRule, f: CorrelationFinding): NormalisedAlert {
  const who = Object.values(f.entity).join(", ");
  return {
    externalId: f.dedupeKey,
    ruleId: rule.id,
    title: `${rule.title} (${who})`,
    description: f.explanation.join("\n"),
    category: rule.category,
    siemSeverity: null,
    severity: rule.severity,
    occurredAt: new Date(f.lastAt),
    assetExternalId: null,
    hostname: f.entity.host ?? null,
    userName: f.entity.user ?? null,
    attackTechniques: rule.techniques,
    routingKeys: [],
    raw: {
      eventType: rule.eventType,
      correlation: { ruleId: rule.id, ruleVersion: rule.version, dedupeKey: f.dedupeKey, entity: f.entity, firstAt: new Date(f.firstAt).toISOString(), matches: f.matches },
    },
  };
}

/** Alert ids a correlated alert was built from, read back from its raw record. */
export function contributingIds(raw: unknown): string[] {
  const c = raw && typeof raw === "object" ? (raw as { correlation?: { matches?: { events?: { id?: unknown }[] }[] } }).correlation : undefined;
  return [...new Set((c?.matches ?? []).flatMap((m) => (m.events ?? []).map((e) => String(e.id ?? ""))).filter(Boolean))];
}
