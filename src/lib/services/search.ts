import net from "node:net";
import { and, eq, exists, inArray, isNull, or } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { assetSources, integrations, integrationTenantLinks, tenantPlans } from "@/db/schema";
import { audit } from "@/lib/audit";
import { assertCan, type AccessContext } from "@/lib/auth/access";
import { asTier, collectionAllowed } from "@/lib/billing/catalogue";
import { eventProvider, type IntegrationRow } from "@/lib/connectors/instances";
import { CONNECTORS, connectorDef, dataCapabilitiesOf } from "@/lib/connectors/registry";
import {
  decodeCursor, encodeCursor, unsupportedFilters,
  type DataCapabilities, type EventEntity, type EventPage, type SearchEvent, type SearchFilters, type SecurityDataProvider, type TenantDataScope,
} from "@/lib/providers/data";
import { SEVERITIES } from "./alerts";
import { actor, inTenant } from "./common";

/**
 * Federated event search. A tenant's search fans out to every enabled source that serves the
 * tenant, in parallel and with a per-source timeout. Each source answers for itself: one failing
 * or slow source is reported and never fails the search.
 *
 * Tenant scoping happens here, not in the caller: a shared integration is only searched through a
 * provider bound to the tenant's agents (asset_sources and the link selector), and a tenant-owned
 * one only for its owner.
 */

export type SourceStatus = "ok" | "partial" | "error" | "unsupported";

export type DataSource = {
  integrationId: string;
  name: string;
  provider: string;
  /** Platform-owned integration shared between tenants. */
  shared: boolean;
  capabilities: DataCapabilities;
  /** Why this source cannot be searched for the tenant (plan, missing adapter). */
  unavailable?: string;
  /** Instantiates the tenant-bound data provider. May throw (bad secrets, refused scope). */
  open: () => SecurityDataProvider;
};

export type SourceResult = {
  integrationId: string;
  name: string;
  provider: string;
  status: SourceStatus;
  message?: string;
  count: number;
  total?: number;
  hasMore: boolean;
  tookMs: number;
};

export type FederatedQuery = {
  from: Date;
  to: Date;
  text?: string;
  filters?: SearchFilters;
  /** Entity pivot: runs `getEntityActivity` instead of a search. */
  entity?: EventEntity;
  pageSize?: number;
  cursor?: string | null;
  includeArchive?: boolean;
};

export type FederatedResult = {
  events: SearchEvent[];
  sources: SourceResult[];
  /** Next page across every source that has more. Null when all are done. */
  cursor: string | null;
};

export const DEFAULT_SOURCE_TIMEOUT_MS = 15_000;

class SourceTimeout extends Error {}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  return Promise.race([p, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new SourceTimeout(`timed out after ${Math.round(ms / 100) / 10}s`)), ms); })]).finally(() => clearTimeout(timer));
}

const isCursorMap = (v: unknown): v is Record<string, string> =>
  !!v && typeof v === "object" && !Array.isArray(v) && Object.values(v).every((c) => typeof c === "string" && c.length <= 4096);

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err)).slice(0, 300);

/** Runs one page of a query over the given sources. Pure apart from the providers it calls. */
export async function federate(sources: DataSource[], q: FederatedQuery, opts: { timeoutMs?: number } = {}): Promise<FederatedResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_SOURCE_TIMEOUT_MS;
  const cursors = q.cursor ? decodeCursor(q.cursor, isCursorMap) : null;
  const filters = q.entity ? undefined : q.filters;

  const run = async (s: DataSource): Promise<{ result: SourceResult; page: EventPage | null }> => {
    const base = { integrationId: s.integrationId, name: s.name, provider: s.provider, count: 0, hasMore: false, tookMs: 0 };
    const unsupported = (message: string) => ({ result: { ...base, status: "unsupported" as const, message }, page: null });
    if (cursors && !(s.integrationId in cursors)) return { result: { ...base, status: "ok", message: "no further results" }, page: null };
    if (s.unavailable) return unsupported(s.unavailable);
    if (q.entity ? !s.capabilities.entityActivity : !s.capabilities.search) return unsupported(q.entity ? "entity activity is not supported" : "search is not supported");
    const missing = unsupportedFilters(filters, s.capabilities);
    if (missing.length) return unsupported(`cannot filter by ${missing.join(", ")}`);
    const started = Date.now();
    try {
      const provider = s.open();
      const cursor = cursors?.[s.integrationId] ?? null;
      const page = await withTimeout(
        q.entity
          ? provider.getEntityActivity(q.entity, { from: q.from, to: q.to }, { pageSize: q.pageSize, cursor })
          : provider.search({ from: q.from, to: q.to, text: q.text, filters, pageSize: q.pageSize, cursor, includeArchive: q.includeArchive }),
        timeoutMs,
      );
      const result: SourceResult = {
        ...base,
        status: page.partial ? "partial" : "ok",
        message: [page.partial, page.notice].filter(Boolean).join("; ") || undefined,
        count: page.events.length,
        total: page.total,
        hasMore: page.cursor !== null,
        tookMs: Date.now() - started,
      };
      return { result, page };
    } catch (err) {
      return { result: { ...base, status: "error", message: errorText(err), tookMs: Date.now() - started }, page: null };
    }
  };

  const settled = await Promise.all(sources.map((s) => run(s).catch((err): { result: SourceResult; page: null } => ({
    result: { integrationId: s.integrationId, name: s.name, provider: s.provider, status: "error", message: errorText(err), count: 0, hasMore: false, tookMs: 0 },
    page: null,
  }))));
  const next: Record<string, string> = {};
  for (const { result, page } of settled) if (page?.cursor) next[result.integrationId] = page.cursor;
  return {
    events: settled.flatMap(({ page }) => page?.events ?? []).sort((a, b) => b.time - a.time),
    sources: settled.map(({ result }) => result),
    cursor: Object.keys(next).length ? encodeCursor(next) : null,
  };
}

/**
 * Every enabled event integration that serves the tenant, bound to the tenant's slice of it.
 * Reads with the system connection because platform-owned integrations are invisible under a
 * tenant scope; every query filters by the tenant explicitly. Callers check access first.
 */
export async function tenantDataSources(tenantId: string): Promise<DataSource[]> {
  const sdb = systemDb();
  const linked = exists(sdb.select().from(integrationTenantLinks).where(and(eq(integrationTenantLinks.integrationId, integrations.id), eq(integrationTenantLinks.tenantId, tenantId))));
  const rows: IntegrationRow[] = (
    await sdb.select().from(integrations).where(and(eq(integrations.enabled, true), or(eq(integrations.tenantId, tenantId), and(isNull(integrations.tenantId), linked))))
  ).filter((r) => connectorDef(r.provider)?.capabilities.includes("events"));
  if (!rows.length) return [];

  const sharedIds = rows.filter((r) => r.tenantId === null).map((r) => r.id);
  const [links, agents, [plan]] = await Promise.all([
    sharedIds.length ? sdb.select().from(integrationTenantLinks).where(and(eq(integrationTenantLinks.tenantId, tenantId), inArray(integrationTenantLinks.integrationId, sharedIds))) : [],
    sharedIds.length
      ? sdb.select({ integrationId: assetSources.integrationId, externalId: assetSources.externalId }).from(assetSources).where(and(eq(assetSources.tenantId, tenantId), inArray(assetSources.integrationId, sharedIds)))
      : [],
    sdb.select({ tier: tenantPlans.tier }).from(tenantPlans).where(eq(tenantPlans.tenantId, tenantId)),
  ]);
  const tier = asTier(plan?.tier ?? "essentials");

  return rows
    .map((row): DataSource => {
      const shared = row.tenantId === null;
      const agentIds: TenantDataScope["agentIds"] = shared
        ? [...new Set([
            ...agents.filter((a) => a.integrationId === row.id).map((a) => a.externalId),
            ...(links.find((l) => l.integrationId === row.id)?.selector.agentIds ?? []),
          ])]
        : "all";
      const scope: TenantDataScope = { tenantId, integrationId: row.id, agentIds };
      return {
        integrationId: row.id,
        name: row.name,
        provider: row.provider,
        shared,
        capabilities: dataCapabilitiesOf(row.provider),
        unavailable: collectionAllowed(tier, row.provider) ? undefined : "not included in the customer's plan",
        open: () => {
          const provider = eventProvider(row);
          if (!provider.dataProvider) throw new Error(`${row.provider} has no search adapter`);
          return provider.dataProvider(scope);
        },
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

export class SearchInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SearchInputError";
  }
}

export type EventSearchInput = FederatedQuery & {
  tenantId: string;
  /** Limit the search to these integrations. */
  integrationIds?: string[];
  timeoutMs?: number;
};

const MAX_RANGE_MS = 400 * 86_400_000;

function checkInput(i: EventSearchInput): void {
  if (Number.isNaN(i.from.getTime()) || Number.isNaN(i.to.getTime())) throw new SearchInputError("invalid time range");
  if (i.from.getTime() >= i.to.getTime()) throw new SearchInputError("the start of the range must be before the end");
  if (i.to.getTime() - i.from.getTime() > MAX_RANGE_MS) throw new SearchInputError("the range cannot be longer than 400 days");
  if ((i.text?.length ?? 0) > 1000) throw new SearchInputError("query is too long");
  const f = i.filters ?? {};
  for (const k of ["host", "user", "ruleId"] as const) if ((f[k]?.length ?? 0) > 200) throw new SearchInputError(`${k} filter is too long`);
  if (f.ip?.trim() && !net.isIP(f.ip.trim())) throw new SearchInputError("ip filter must be an IP address");
  if (f.severity?.some((s) => !(SEVERITIES as readonly string[]).includes(s))) throw new SearchInputError("unknown severity");
  if (i.entity && (!["host", "user", "ip"].includes(i.entity.type) || !i.entity.value.trim() || i.entity.value.length > 200)) throw new SearchInputError("invalid entity");
  if (i.entity?.type === "ip" && !net.isIP(i.entity.value.trim())) throw new SearchInputError("entity ip must be an IP address");
}

/**
 * Search one tenant's events in place across its sources. Needs `alert:triage` in the tenant, the
 * same permission that shows raw alert payloads. The first page of each search is audited.
 */
export async function searchTenantEvents(ctx: AccessContext, input: EventSearchInput): Promise<FederatedResult> {
  assertCan(ctx, "alert:triage", input.tenantId);
  checkInput(input);
  if (!input.cursor) {
    await inTenant(ctx, "alert:triage", input.tenantId, (tx) =>
      audit(tx, {
        ...actor(ctx),
        tenantId: input.tenantId,
        action: input.entity ? "event.entity_activity" : "event.search",
        targetType: "tenant",
        targetId: input.tenantId,
        detail: { text: input.text ?? null, filters: input.filters ?? {}, entity: input.entity ?? null, from: input.from.toISOString(), to: input.to.toISOString(), includeArchive: !!input.includeArchive },
      }),
    );
  }
  const all = await tenantDataSources(input.tenantId);
  const sources = input.integrationIds?.length ? all.filter((s) => input.integrationIds!.includes(s.integrationId)) : all;
  return federate(sources, input, { timeoutMs: input.timeoutMs });
}

/** Everything one tenant's sources record about a host, user or IP in the range. */
export function tenantEntityActivity(ctx: AccessContext, tenantId: string, entity: EventEntity, range: { from: Date; to: Date }, page: { pageSize?: number; cursor?: string | null } = {}): Promise<FederatedResult> {
  return searchTenantEvents(ctx, { tenantId, entity, ...range, ...page });
}

/** One event by its provider id, read in place. Null when it is not the tenant's or does not exist. */
export async function getTenantEvent(ctx: AccessContext, tenantId: string, integrationId: string, eventId: string): Promise<SearchEvent | null> {
  assertCan(ctx, "alert:triage", tenantId);
  const source = (await tenantDataSources(tenantId)).find((s) => s.integrationId === integrationId);
  if (!source || source.unavailable || !source.capabilities.getEvent) return null;
  return source.open().getEvent(eventId);
}

export type DataSourceInfo = {
  integrationId: string;
  name: string;
  provider: string;
  shared: boolean;
  capabilities: DataCapabilities;
  available: boolean;
  reason?: string;
};

/** Capability discovery for one tenant: which of its sources can be searched, and how. */
export async function listTenantDataSources(ctx: AccessContext, tenantId: string): Promise<DataSourceInfo[]> {
  assertCan(ctx, "alert:triage", tenantId);
  return (await tenantDataSources(tenantId)).map((s) => {
    const reason = s.unavailable ?? (s.capabilities.search ? undefined : "search is not supported");
    return { integrationId: s.integrationId, name: s.name, provider: s.provider, shared: s.shared, capabilities: s.capabilities, available: !reason, ...(reason ? { reason } : {}) };
  });
}

/** Declared data capabilities of every connector in the catalogue. Static; no tenant data. */
export function connectorDataCapabilities(): { provider: string; name: string; status: "available" | "planned"; data: DataCapabilities }[] {
  return CONNECTORS.filter((c) => c.capabilities.includes("events")).map((c) => ({ provider: c.provider, name: c.name, status: c.status, data: dataCapabilitiesOf(c.provider) }));
}
