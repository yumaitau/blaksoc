import type { OcsfEvent } from "@/lib/ocsf/schema";
import type { ProviderHealth, Severity } from "./types";

/**
 * Query-in-place contract. A `SecurityDataProvider` reads a source's events where they live and
 * returns them as OCSF events with provenance; nothing is copied into Postgres.
 *
 * An instance is bound to one tenant's slice of one integration (`TenantDataScope`): every search,
 * event lookup and entity query it runs is filtered to that tenant's agents or sources. Callers
 * never pass tenant filters themselves.
 */

export type SearchFilterField = "severity" | "host" | "user" | "ip" | "ruleId";

export type DataCapabilities = {
  search: boolean;
  getEvent: boolean;
  entityActivity: boolean;
  /** OCSF class_uids search results can carry. */
  ocsfClasses: number[];
  /** Longest window one search may cover. Longer requests are clamped to the most recent window. Null: no limit. */
  maxRangeMs: number | null;
  paging: "cursor" | "none";
  maxPageSize: number;
  /** Free-text query, and the syntax it uses. */
  freeText: "none" | "substring" | "lucene";
  /** Typed filters the provider applies at the source. A query using another filter is not sent to it. */
  filters: SearchFilterField[];
  /** Hot: online store. Cold: archive tier (searched when the query asks for it). */
  tiers: ("hot" | "cold")[];
};

export const NO_DATA_CAPABILITIES: DataCapabilities = {
  search: false,
  getEvent: false,
  entityActivity: false,
  ocsfClasses: [],
  maxRangeMs: null,
  paging: "none",
  maxPageSize: 0,
  freeText: "none",
  filters: [],
  tiers: [],
};

export type SearchFilters = {
  severity?: Severity[];
  host?: string;
  user?: string;
  ip?: string;
  ruleId?: string;
};

export type EventSearchQuery = {
  from: Date;
  to: Date;
  text?: string;
  filters?: SearchFilters;
  pageSize?: number;
  /** Opaque cursor from the previous page of this provider. */
  cursor?: string | null;
  /** Also search the cold tier where the provider has one. */
  includeArchive?: boolean;
};

export type EventEntity = { type: "host" | "user" | "ip"; value: string };

/** Where a search result came from. `metadata` on the OCSF event carries the same in OCSF terms. */
export type EventProvenance = {
  integrationId: string;
  /** Connector key, e.g. `wazuh`, `syslog`. */
  provider: string;
  tenantId: string;
  tier: "hot" | "cold";
  /** Index, table or archive region the record was read from. */
  location: string;
};

export type SearchEvent = {
  /** Provider-scoped id; `getEvent(id)` returns the same record. */
  id: string;
  /** Event time, epoch ms (same as `ocsf.time`). */
  time: number;
  ocsf: OcsfEvent;
  provenance: EventProvenance;
  /** The source record as read. SOC-only, like `alerts.raw`. */
  raw: Record<string, unknown> | string;
};

export type EventPage = {
  events: SearchEvent[];
  /** Pass back as `cursor` for the next page. Null: no more results. */
  cursor: string | null;
  /** Total matches when the source reports one. */
  total?: number;
  /** Set when the page is incomplete (range clamped, archive scan capped). */
  partial?: string;
  /** Informational note, e.g. no agents mapped to the tenant yet. */
  notice?: string;
};

export type TenantDataScope = {
  tenantId: string;
  integrationId: string;
  /** Provider asset ids (e.g. Wazuh agent ids) that belong to the tenant, or "all" when the tenant owns the whole source. */
  agentIds: readonly string[] | "all";
};

export interface SecurityDataProvider {
  readonly kind: string;
  capabilities(): DataCapabilities;
  search(q: EventSearchQuery): Promise<EventPage>;
  getEvent(id: string): Promise<SearchEvent | null>;
  getEntityActivity(entity: EventEntity, range: { from: Date; to: Date }, page?: { pageSize?: number; cursor?: string | null }): Promise<EventPage>;
  health(): Promise<ProviderHealth>;
}

export const DAY_MS = 86_400_000;

export function pageSizeFor(q: { pageSize?: number }, caps: DataCapabilities, fallback = 50): number {
  const n = Math.floor(q.pageSize ?? fallback);
  return Math.max(1, Math.min(Number.isFinite(n) ? n : fallback, caps.maxPageSize || fallback));
}

/** Clamp the window to the provider's limit, keeping the most recent part. */
export function clampRange(q: { from: Date; to: Date }, caps: DataCapabilities): { from: Date; to: Date; clamped: boolean } {
  if (caps.maxRangeMs === null || q.to.getTime() - q.from.getTime() <= caps.maxRangeMs) return { from: q.from, to: q.to, clamped: false };
  return { from: new Date(q.to.getTime() - caps.maxRangeMs), to: q.to, clamped: true };
}

/** Typed filters in the query that the provider cannot apply. */
export function unsupportedFilters(filters: SearchFilters | undefined, caps: DataCapabilities): SearchFilterField[] {
  if (!filters) return [];
  return (Object.keys(filters) as SearchFilterField[]).filter((k) => {
    const v = filters[k];
    const set = Array.isArray(v) ? v.length > 0 : typeof v === "string" ? v.trim() !== "" : v !== undefined;
    return set && !caps.filters.includes(k);
  });
}

export function entityFilters(entity: EventEntity): SearchFilters {
  return entity.type === "host" ? { host: entity.value } : entity.type === "user" ? { user: entity.value } : { ip: entity.value };
}

export function encodeCursor(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/** Decodes a cursor this module encoded. Anything else is treated as no cursor. */
export function decodeCursor<T>(cursor: string | null | undefined, check: (v: unknown) => v is T): T | null {
  if (!cursor) return null;
  try {
    const v: unknown = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    return check(v) ? v : null;
  } catch {
    return null;
  }
}

/** Display fields for a search result, read from its OCSF event. */
export function eventSummary(e: OcsfEvent): { title: string; className: string; severity: string; host: string | null; user: string | null; src: string | null; dst: string | null } {
  const rec = e as unknown as Record<string, unknown>;
  const obj = (k: string) => (rec[k] && typeof rec[k] === "object" ? (rec[k] as Record<string, unknown>) : undefined);
  const s = (v: unknown) => (typeof v === "string" && v ? v : null);
  const evidence = Array.isArray(rec.evidences) ? (rec.evidences[0] as Record<string, Record<string, unknown> | undefined> | undefined) : undefined;
  const finding = obj("finding_info");
  const endpoint = (o: Record<string, unknown> | undefined) => (o ? [s(o.ip) ?? s(o.hostname), o.port !== undefined ? String(o.port) : null].filter(Boolean).join(":") || null : null);
  return {
    title: s(finding?.title) ?? s(rec.message) ?? s(rec.class_name) ?? "Event",
    className: s(rec.class_name) ?? `class ${String(rec.class_uid)}`,
    severity: (s(rec.severity) ?? "Unknown").toLowerCase(),
    host: s(obj("device")?.hostname) ?? s(evidence?.device?.hostname) ?? null,
    user: s(obj("user")?.name) ?? s(evidence?.user?.name) ?? null,
    src: endpoint(obj("src_endpoint")),
    dst: endpoint(obj("dst_endpoint")),
  };
}
