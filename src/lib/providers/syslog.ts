import { and, asc, eq, gt, ilike, or, sql } from "drizzle-orm";
import { withScope } from "@/db/scope";
import { syslogEvents } from "@/db/schema";
import { systemScope } from "@/lib/auth/access";
import { normaliseSyslog } from "@/lib/syslog/parse";
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
