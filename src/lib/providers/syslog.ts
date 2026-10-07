import { and, asc, desc, eq, gt, gte, ilike, lt, lte, or, sql, type SQL } from "drizzle-orm";
import { withScope } from "@/db/scope";
import { syslogArchive, syslogEvents } from "@/db/schema";
import { systemScope } from "@/lib/auth/access";
import { defaultArchiveStore, type ArchiveStore } from "@/lib/hosting/store";
import { syslogToNetworkActivity, toBaseEvent, type Provenance } from "@/lib/ocsf/map";
import { scanArchive, type ArchiveKey } from "@/lib/syslog/archive";
import { normaliseSyslog } from "@/lib/syslog/parse";
import {
  clampRange, DAY_MS, decodeCursor, encodeCursor, entityFilters, pageSizeFor,
  type DataCapabilities, type EventEntity, type EventPage, type EventSearchQuery, type SearchEvent, type SecurityDataProvider, type TenantDataScope,
} from "./data";
import type { AlertQuery, NormalisedAlert, NormalisedAsset, ProviderHealth, ResponseActionRequest, ResponseActionResult, SecurityEventProvider } from "./types";

function cursorWhere(cursor: string | undefined) {
  if (!cursor) return undefined;
  const pipe = cursor.lastIndexOf("|");
  if (pipe <= 0) return undefined;
  const at = new Date(cursor.slice(0, pipe));
  const id = cursor.slice(pipe + 1);
  if (Number.isNaN(at.getTime()) || !id) return undefined;
  return or(gt(syslogEvents.ingestedAt, at), and(eq(syslogEvents.ingestedAt, at), gt(syslogEvents.id, id)));
}

/** Reads hot syslog lines for one tenant and returns them as normalised alerts. */
export class SyslogProvider implements SecurityEventProvider {
  readonly kind = "syslog";

  constructor(private readonly tenantId: string) {}

  private hot(extra?: ReturnType<typeof cursorWhere>) {
    return and(eq(syslogEvents.tenantId, this.tenantId), eq(syslogEvents.tier, "hot"), extra);
  }

  async getAlerts(q: AlertQuery): Promise<{ alerts: NormalisedAlert[]; cursor: string | null }> {
    if (!this.tenantId) return { alerts: [], cursor: null };
    const limit = Math.min(q.limit ?? 200, 500);
    const rows = await withScope(systemScope(this.tenantId), (tx) =>
      tx
        .select()
        .from(syslogEvents)
        .where(this.hot(cursorWhere(q.afterCursor)))
        .orderBy(asc(syslogEvents.ingestedAt), asc(syslogEvents.id))
        .limit(limit),
    );
    const alerts = rows.flatMap((row) => {
      const alert = normaliseSyslog(row, this.tenantId);
      return alert ? [alert] : [];
    });
    const last = rows.at(-1);
    return { alerts, cursor: last ? `${last.ingestedAt.toISOString()}|${last.id}` : (q.afterCursor ?? null) };
  }

  async getAlert(externalId: string): Promise<NormalisedAlert | null> {
    const [row] = await withScope(systemScope(this.tenantId), (tx) =>
      tx.select().from(syslogEvents).where(and(eq(syslogEvents.tenantId, this.tenantId), eq(syslogEvents.id, externalId), eq(syslogEvents.tier, "hot"))),
    );
    return row ? normaliseSyslog(row, this.tenantId) : null;
  }

  async searchEvents(q: AlertQuery): Promise<{ total: number; events: Record<string, unknown>[] }> {
    const needle = q.query?.slice(0, 200);
    const rows = await withScope(systemScope(this.tenantId), (tx) =>
      tx
        .select()
        .from(syslogEvents)
        .where(this.hot(needle ? ilike(syslogEvents.line, `%${needle}%`) : undefined))
        .orderBy(asc(syslogEvents.ingestedAt))
        .limit(Math.min(q.limit ?? 100, 100)),
    );
    return { total: rows.length, events: rows.map((row) => ({ id: row.id, line: row.line, vendor: row.vendor, ingestedAt: row.ingestedAt.toISOString() })) };
  }

  async getAssets(): Promise<NormalisedAsset[]> {
    return [];
  }

  async getAsset(): Promise<NormalisedAsset | null> {
    return null;
  }

  supportedActions(): ResponseActionRequest["action"][] {
    return [];
  }

  async executeResponseAction(): Promise<ResponseActionResult> {
    return { ok: false, message: "syslog ingest does not run response actions" };
  }

  /** Syslog belongs to one tenant: the integration's stamped owner. Any other scope is refused. */
  dataProvider(scope: TenantDataScope): SecurityDataProvider {
    if (!this.tenantId || scope.tenantId !== this.tenantId) throw new Error("syslog integration belongs to another tenant");
    return new SyslogDataProvider(scope);
  }

  async health(): Promise<ProviderHealth> {
    const started = Date.now();
    try {
      const [row] = await withScope(systemScope(this.tenantId), (tx) =>
        tx.select({ n: sql<number>`count(*)::int` }).from(syslogEvents).where(this.hot()),
      );
      return { ok: true, latencyMs: Date.now() - started, detail: { hot: row?.n ?? 0 } };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - started, detail: {}, error: err instanceof Error ? err.message : "syslog health failed" };
    }
  }
}

export const SYSLOG_DATA_CAPABILITIES: DataCapabilities = {
  search: true,
  getEvent: true,
  entityActivity: true,
  ocsfClasses: [4001, 0],
  maxRangeMs: 400 * DAY_MS,
  paging: "cursor",
  maxPageSize: 200,
  freeText: "substring",
  // Matched as case-insensitive substrings of the line.
  filters: ["host", "user", "ip"],
  tiers: ["hot", "cold"],
};

/** Objects one search reads from the cold archive before returning a short page with a cursor. */
const ARCHIVE_SCAN_LIMIT = 2000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type TierCursor = [string, string] | "done";
type SyslogCursor = { hot?: TierCursor; cold?: TierCursor };

const isTierCursor = (v: unknown): v is TierCursor =>
  v === "done" || (Array.isArray(v) && v.length === 2 && typeof v[0] === "string" && !Number.isNaN(Date.parse(v[0])) && typeof v[1] === "string" && UUID.test(v[1]));
const isSyslogCursor = (v: unknown): v is SyslogCursor =>
  !!v && typeof v === "object" && !Array.isArray(v) && Object.entries(v).every(([k, c]) => (k === "hot" || k === "cold") && isTierCursor(c));

const keyOf = (c: TierCursor | undefined): ArchiveKey | null => (Array.isArray(c) ? { at: new Date(c[0]), id: c[1] } : null);
const likeEscape = (v: string) => v.replace(/[\\%_]/g, (c) => `\\${c}`);

type Line = { id: string; line: string; receivedAt: Date; tier: "hot" | "cold"; location: string };

/**
 * One tenant's firewall syslog: hot lines in Postgres and, when asked, cold lines in the AU archive
 * (read from the object store through scanArchive). Time bounds apply to receive time. Every query
 * is filtered to the tenant and runs under that tenant's RLS scope.
 */
export class SyslogDataProvider implements SecurityDataProvider {
  readonly kind = "syslog";
  private readonly tenantId: string;

  constructor(private readonly scope: TenantDataScope, private readonly store?: ArchiveStore) {
    this.tenantId = scope.tenantId;
  }

  capabilities(): DataCapabilities {
    return SYSLOG_DATA_CAPABILITIES;
  }

  private archive(): ArchiveStore {
    return this.store ?? defaultArchiveStore();
  }

  private toEvent(l: Line): SearchEvent {
    const p: Provenance = { source: "syslog", sourceEventId: l.id, tenantId: this.tenantId, ingestedAt: l.receivedAt };
    const alert = normaliseSyslog({ id: l.id, line: l.line, byteLen: Buffer.byteLength(l.line), ingestedAt: l.receivedAt }, this.tenantId);
    const ocsf =
      (alert && syslogToNetworkActivity(alert, p)) ??
      toBaseEvent(
        {
          time: alert?.occurredAt ?? l.receivedAt,
          message: alert?.title ?? l.line.slice(0, 200),
          severity: alert?.severity ?? "informational",
          device: alert?.hostname ? { type_id: 9, hostname: alert.hostname } : undefined,
          user: alert?.userName ? { name: alert.userName } : undefined,
        },
        p,
      );
    return {
      id: l.id,
      time: ocsf.time,
      ocsf,
      provenance: { integrationId: this.scope.integrationId, provider: "syslog", tenantId: this.tenantId, tier: l.tier, location: l.location },
      raw: alert?.raw ?? { line: l.line },
    };
  }

  async search(q: EventSearchQuery): Promise<EventPage> {
    const caps = this.capabilities();
    const range = clampRange(q, caps);
    const size = pageSizeFor(q, caps);
    const cur = decodeCursor(q.cursor, isSyslogCursor) ?? {};
    const terms = [q.text, q.filters?.host, q.filters?.user, q.filters?.ip].map((t) => t?.trim().slice(0, 200)).filter((t): t is string => !!t);
    const lowered = terms.map((t) => t.toLowerCase());

    const hotKey = keyOf(cur.hot);
    const hotRows: Line[] =
      cur.hot === "done"
        ? []
        : (
            await withScope(systemScope(this.tenantId), (tx) => {
              const where: (SQL | undefined)[] = [
                eq(syslogEvents.tenantId, this.tenantId),
                eq(syslogEvents.tier, "hot"),
                gte(syslogEvents.ingestedAt, range.from),
                lte(syslogEvents.ingestedAt, range.to),
                ...terms.map((t) => ilike(syslogEvents.line, `%${likeEscape(t)}%`)),
              ];
              if (hotKey) where.push(or(lt(syslogEvents.ingestedAt, hotKey.at), and(eq(syslogEvents.ingestedAt, hotKey.at), lt(syslogEvents.id, hotKey.id))));
              return tx
                .select({ id: syslogEvents.id, line: syslogEvents.line, receivedAt: syslogEvents.ingestedAt })
                .from(syslogEvents)
                .where(and(...where))
                .orderBy(desc(syslogEvents.ingestedAt), desc(syslogEvents.id))
                .limit(size + 1);
            })
          ).map((r) => ({ ...r, tier: "hot" as const, location: "syslog_events" }));

    const wantCold = q.includeArchive === true && cur.cold !== "done";
    const scan = wantCold
      ? await scanArchive(this.tenantId, this.archive(), {
          match: (line) => {
            const l = line.toLowerCase();
            return lowered.every((t) => l.includes(t));
          },
          from: range.from,
          to: range.to,
          before: keyOf(cur.cold),
          limit: size,
          scanLimit: ARCHIVE_SCAN_LIMIT,
          onMissing: "skip",
        })
      : null;
    const coldRows: Line[] = (scan?.hits ?? []).map((h) => ({ id: h.eventId, line: h.line, receivedAt: h.receivedAt, tier: "cold", location: `archive:${h.region}` }));

    // Merge newest first on receive time, then cut to one page. Each tier resumes after its last shown row.
    const hotPage = hotRows.slice(0, size);
    const page = [...hotPage, ...coldRows]
      .sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime() || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0))
      .slice(0, size);
    const shownHot = page.filter((l) => l.tier === "hot");
    const shownCold = page.filter((l) => l.tier === "cold");
    const at = (l: Line): TierCursor => [l.receivedAt.toISOString(), l.id];

    let nextHot: TierCursor | undefined;
    if (cur.hot === "done") nextHot = "done";
    else if (shownHot.length === hotPage.length && hotRows.length <= size) nextHot = "done";
    else nextHot = shownHot.length ? at(shownHot.at(-1)!) : cur.hot;

    let nextCold: TierCursor | undefined;
    if (!q.includeArchive || cur.cold === "done") nextCold = "done";
    else if (shownCold.length === coldRows.length) nextCold = scan!.exhausted ? "done" : scan!.last ? [scan!.last.at.toISOString(), scan!.last.id] : "done";
    else nextCold = shownCold.length ? at(shownCold.at(-1)!) : cur.cold;

    const problems = [
      range.clamped ? `range limited to the last ${Math.round((caps.maxRangeMs ?? 0) / DAY_MS)} days` : null,
      scan?.missing ? `${scan.missing} archived object(s) missing from the store` : null,
    ].filter(Boolean);
    return {
      events: page.map((l) => this.toEvent(l)),
      cursor: nextHot === "done" && nextCold === "done" ? null : encodeCursor({ hot: nextHot, cold: nextCold } satisfies SyslogCursor),
      ...(problems.length ? { partial: problems.join("; ") } : {}),
      ...(scan && !scan.exhausted && shownCold.length === coldRows.length && coldRows.length < size ? { notice: `archive scan stopped after ${ARCHIVE_SCAN_LIMIT} objects; the next page continues it` } : {}),
    };
  }

  async getEvent(id: string): Promise<SearchEvent | null> {
    if (!UUID.test(id)) return null;
    const found = await withScope(systemScope(this.tenantId), async (tx) => {
      const [row] = await tx
        .select({ id: syslogEvents.id, line: syslogEvents.line, tier: syslogEvents.tier, receivedAt: syslogEvents.ingestedAt })
        .from(syslogEvents)
        .where(and(eq(syslogEvents.tenantId, this.tenantId), eq(syslogEvents.id, id)));
      if (!row) return null;
      if (row.tier === "hot") return { kind: "hot" as const, row };
      const [arc] = await tx.select().from(syslogArchive).where(and(eq(syslogArchive.tenantId, this.tenantId), eq(syslogArchive.eventId, id)));
      return arc ? { kind: "cold" as const, row, arc } : null;
    });
    if (!found) return null;
    if (found.kind === "hot") return this.toEvent({ id, line: found.row.line, receivedAt: found.row.receivedAt, tier: "hot", location: "syslog_events" });
    try {
      const line = await this.archive().get(found.arc.region, found.arc.objectKey);
      return this.toEvent({ id, line, receivedAt: found.row.receivedAt, tier: "cold", location: `archive:${found.arc.region}` });
    } catch {
      return null;
    }
  }

  getEntityActivity(entity: EventEntity, range: { from: Date; to: Date }, page: { pageSize?: number; cursor?: string | null } = {}): Promise<EventPage> {
    return this.search({ ...range, ...page, filters: entityFilters(entity), includeArchive: true });
  }

  health(): Promise<ProviderHealth> {
    return new SyslogProvider(this.tenantId).health();
  }
}
