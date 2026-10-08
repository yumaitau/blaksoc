import type { RiskFactor } from "@/db/schema";
import { LEVEL_BANDS } from "@/lib/providers/wazuh";
import type { Severity } from "@/lib/providers/types";

/** One labelled fact about where an alert came from, ready to show. */
export type SourceField = { label: string; value: string };

const SOURCE_LABELS: Record<string, string> = {
  wazuh: "Wazuh",
  syslog: "Firewall syslog",
  tawny: "Tawny EDR",
  entra: "Microsoft Entra ID",
  "google-workspace": "Google Workspace",
  veeam: "Veeam",
  asm: "Attack surface monitoring",
  "email-posture": "Email posture check",
  "credential-exposure": "Credential exposure monitoring",
  "blaksoc-sigma": "Sigma detection",
  "blaksoc-correlation": "Correlation engine",
};

export const sourceLabel = (source: string) => SOURCE_LABELS[source] ?? source;

/** Raw payloads are arbitrary JSON: every read below goes through these and never throws. */
const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

function at(raw: unknown, path: string): unknown {
  let cur: unknown = raw;
  for (const part of path.split(".")) cur = obj(cur)?.[part];
  return cur;
}

function text(v: unknown, max = 200): string | null {
  if (typeof v === "string") {
    const s = v.trim();
    return s ? (s.length > max ? `${s.slice(0, max - 1)}…` : s) : null;
  }
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  if (typeof v === "boolean") return String(v);
  return null;
}

function list(v: unknown, max = 8): string | null {
  if (!Array.isArray(v)) return text(v);
  const items = v.map((x) => text(x, 60)).filter((x): x is string => !!x);
  if (!items.length) return null;
  return items.length > max ? `${items.slice(0, max).join(", ")} +${items.length - max}` : items.join(", ");
}

const join = (...parts: (string | null)[]) => parts.filter(Boolean).join(" ") || null;
const hostPort = (ip: unknown, port: unknown) => (text(ip) ? (text(port) ? `${text(ip)}:${text(port)}` : text(ip)) : null);

function fields(pairs: [string, string | null][]): SourceField[] {
  return pairs.filter((p): p is [string, string] => !!p[1]).map(([label, value]) => ({ label, value }));
}

function wazuhFields(raw: unknown): SourceField[] {
  const agentIp = text(at(raw, "agent.ip"));
  const agentId = text(at(raw, "agent.id"));
  return fields([
    ["Rule", text(at(raw, "rule.id"))],
    ["Rule description", text(at(raw, "rule.description"))],
    ["Rule level", text(at(raw, "rule.level"))],
    ["Rule groups", list(at(raw, "rule.groups"))],
    ["Decoder", text(at(raw, "decoder.name"))],
    ["Location", text(at(raw, "location"))],
    ["Agent", join(text(at(raw, "agent.name")), agentIp ? `(${agentIp})` : null, agentId ? `· id ${agentId}` : null)],
    ["Manager", text(at(raw, "manager.name"))],
  ]);
}

function syslogFields(raw: unknown): SourceField[] {
  return fields([
    ["Vendor", text(at(raw, "vendor"))],
    ["Action", text(at(raw, "action"))],
    ["Source", hostPort(at(raw, "srcIp"), at(raw, "srcPort"))],
    ["Destination", hostPort(at(raw, "dstIp"), at(raw, "dstPort"))],
    ["Protocol", text(at(raw, "proto"))],
    ["Line", text(at(raw, "line"), 300)],
  ]);
}

function tawnyFields(raw: unknown): SourceField[] {
  return fields([
    ["Rule", join(text(at(raw, "alert.rule_name")), text(at(raw, "alert.alert_rule_id")) ? `(${text(at(raw, "alert.alert_rule_id"))})` : null)],
    ["Event type", text(at(raw, "alert.event_type"))],
    ["Tawny severity", text(at(raw, "alert.severity"))],
    ["Agent", join(text(at(raw, "agent.name")), text(at(raw, "agent.os.platform")) ? `(${text(at(raw, "agent.os.platform"))})` : null)],
  ]);
}

function correlationFields(raw: unknown): SourceField[] {
  const entity = obj(at(raw, "correlation.entity"));
  const matches = at(raw, "correlation.matches");
  const events = Array.isArray(matches) ? new Set(matches.flatMap((m) => { const e = obj(m)?.events; return Array.isArray(e) ? e.map((x) => text(obj(x)?.id)) : []; }).filter(Boolean)).size : 0;
  return fields([
    ["Correlation rule", join(text(at(raw, "correlation.ruleId")), text(at(raw, "correlation.ruleVersion")) ? `v${text(at(raw, "correlation.ruleVersion"))}` : null)],
    ["Entity", entity ? Object.entries(entity).map(([k, v]) => `${k} ${text(v) ?? "?"}`).join(", ") || null : null],
    ["First matching event", text(at(raw, "correlation.firstAt"))],
    ["Contributing alerts", events ? String(events) : null],
  ]);
}

function sigmaFields(raw: unknown): SourceField[] {
  return fields([
    ["Matched event", text(at(raw, "_id"))],
    ["Agent", join(text(at(raw, "agent.name")), text(at(raw, "agent.id")) ? `· id ${text(at(raw, "agent.id"))}` : null)],
  ]);
}

/** Top-level scalar fields, for providers without a dedicated reader. */
function genericFields(raw: unknown, max = 8): SourceField[] {
  const o = obj(raw);
  if (!o) return [];
  return fields(Object.entries(o).map(([k, v]): [string, string | null] => [k, text(v, 120)])).slice(0, max);
}

/** The source record's identifying fields, read defensively from `raw`. Empty when raw is withheld or unreadable. */
export function sourceFields(source: string, raw: unknown): SourceField[] {
  if (raw == null) return [];
  if (source === "wazuh") return wazuhFields(raw);
  if (source === "syslog") return syslogFields(raw);
  if (source === "tawny") return tawnyFields(raw);
  if (source === "blaksoc-correlation") return correlationFields(raw);
  if (source === "blaksoc-sigma") return sigmaFields(raw);
  return genericFields(raw);
}

/** "10–12" or "13 and above". */
export function wazuhBand(severity: Severity): string {
  const b = LEVEL_BANDS[severity];
  return b.lte == null ? `${b.gte} and above` : `${b.gte}–${b.lte}`;
}

/**
 * One sentence on how the source event got its blakSOC severity. `raw` may be null (withheld from
 * the viewer); the sentence then uses stored columns only.
 */
export function severityReason(a: { source: string; ruleId: string | null; siemSeverity: number | null; severity: Severity; raw: unknown }, ruleTitle?: string | null): string {
  const rule = a.ruleId ? ` ${a.ruleId}` : "";
  switch (a.source) {
    case "wazuh": {
      const level = a.siemSeverity ?? (typeof at(a.raw, "rule.level") === "number" ? (at(a.raw, "rule.level") as number) : null);
      if (level == null) return `Wazuh rule${rule} fired; blakSOC stores it as ${a.severity}.`;
      return `Wazuh rule${rule} fired at level ${level}; blakSOC maps level ${wazuhBand(a.severity)} to ${a.severity}.`;
    }
    case "blaksoc-sigma":
      return `blakSOC Sigma rule${rule} matched an event in the SIEM; the rule is rated ${a.severity}.`;
    case "blaksoc-correlation":
      return `blakSOC correlation rule ${ruleTitle ? `“${ruleTitle}”` : rule.trim() || "(unknown)"} matched a pattern across other alerts; the rule is rated ${a.severity}.`;
    case "syslog": {
      const action = text(at(a.raw, "action"));
      return action
        ? `A firewall log line was parsed as “${action}”; blakSOC rates it ${a.severity} from the action and keywords in the line.`
        : `A firewall log line was parsed into an event; blakSOC rates it ${a.severity} from the action and keywords in the line.`;
    }
    case "tawny": {
      const native = text(at(a.raw, "alert.severity"));
      return native ? `Tawny rated it ${native}; blakSOC stores it as ${a.severity}.` : `Tawny raised it; blakSOC stores it as ${a.severity}.`;
    }
    default:
      return a.siemSeverity != null
        ? `${sourceLabel(a.source)} reported severity ${a.siemSeverity}${rule ? ` for rule${rule}` : ""}; blakSOC stores it as ${a.severity}.`
        : `${sourceLabel(a.source)} raised it${rule ? ` (rule${rule})` : ""} at ${a.severity} severity.`;
  }
}

/** The integration's alert floor as a sentence: "Stores low and above". */
export function floorSentence(floor: Severity): string {
  return floor === "informational" ? "Stores every severity" : `Stores ${floor} and above`;
}

/** Compact duration: "under a second", "42 s", "3 min 12 s", "2 h 5 min", "3 d 4 h". Sign is ignored. */
export function formatDuration(ms: number): string {
  const s = Math.round(Math.abs(ms) / 1000);
  if (s < 1) return "under a second";
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m} min ${s % 60} s` : `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d} d ${h % 24} h` : `${d} d`;
}

/** Event time to storage time, in words. A negative gap means the source clock runs ahead of blakSOC's. */
export function ingestDelay(occurredAt: Date, ingestedAt: Date): string {
  const ms = ingestedAt.getTime() - occurredAt.getTime();
  if (!Number.isFinite(ms)) return "unknown delay";
  if (ms < 0) return `stored ${formatDuration(ms)} before the event time (the source clock is ahead)`;
  return `stored ${formatDuration(ms)} after the event`;
}

/** The factors that moved the risk score most, largest first. */
export function topFactors(factors: RiskFactor[], n = 3): RiskFactor[] {
  return [...factors].filter((f) => f.points > 0).sort((a, b) => b.points - a.points).slice(0, n);
}
