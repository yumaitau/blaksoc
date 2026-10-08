import { looksLikeHostname } from "./pii";

/**
 * Static rule metadata a tuning agent may see. Read field by field from the source event and checked against
 * strict shapes; anything free-form (rule.description, full_log, data.*) is never read, because SIEMs embed
 * user names, hosts and addresses there.
 */

export type RuleMetadata = { level: number | null; groups: string[]; mitre: string[]; decoder: string | null };

/** Identifier-like tokens only: letters, digits and _ . : - (no spaces, @ or slashes). */
const TOKEN = /^[A-Za-z0-9_.:-]{1,64}$/;
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** A source, rule id or group name safe to hand out: an identifier, not an address, a host or an email. */
export function safeToken(v: unknown, max = 64): string | null {
  if (typeof v !== "string" || v.length > max) return null;
  if (!/^[A-Za-z0-9_.:-]+$/.test(v) || IPV4.test(v) || (v.includes(":") && /^[0-9a-f:]+$/i.test(v)) || looksLikeHostname(v)) return null;
  return v;
}

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});

export function ruleMetadata(raw: unknown, techniques: readonly string[] = []): RuleMetadata {
  const rule = obj(obj(raw).rule);
  const level = typeof rule.level === "number" && Number.isInteger(rule.level) && rule.level >= 0 && rule.level <= 20 ? rule.level : null;
  const groups = Array.isArray(rule.groups) ? rule.groups.filter((g): g is string => safeToken(g) !== null && TOKEN.test(g)).slice(0, 20) : [];
  const ruleMitre = Array.isArray(obj(rule.mitre).id) ? (obj(rule.mitre).id as unknown[]) : [];
  const mitre = [...new Set([...ruleMitre, ...techniques].filter((t): t is string => typeof t === "string" && TECHNIQUE.test(t)))].slice(0, 20);
  const decoderName = obj(obj(raw).decoder).name;
  const decoder = safeToken(decoderName) && TOKEN.test(decoderName as string) ? (decoderName as string) : null;
  return { level, groups, mitre, decoder };
}
