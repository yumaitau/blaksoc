import { and, desc, eq, lt, or, sql, type SQL } from "drizzle-orm";
import { withScope } from "@/db/scope";
import { syslogArchive, syslogEvents } from "@/db/schema";
import { systemScope } from "@/lib/auth/access";
import type { ArchiveStore } from "@/lib/hosting/store";

export type ArchiveHit = { eventId: string; region: string; line: string; receivedAt: Date };
export type ArchiveKey = { at: Date; id: string };

export type ArchiveScan = {
  hits: ArchiveHit[];
  /** Last archive row read. Continue from here with `before`. */
  last: ArchiveKey | null;
  /** Every row in range was read. */
  exhausted: boolean;
  /** Rows whose object was missing from the store (skipped when `onMissing` is "skip"). */
  missing: number;
};

/**
 * Archived syslog lines for one tenant, newest first by receive time. Lines are read from the AU
 * object store; the Postgres `body` column is not the source. `scanLimit` caps how many objects one
 * call reads, so a wide range over a large archive returns a short page with a cursor instead of
 * reading everything.
 */
export async function scanArchive(
  tenantId: string,
  store: ArchiveStore,
  opts: {
    match?: (line: string) => boolean;
    from?: Date;
    to?: Date;
    before?: ArchiveKey | null;
    limit?: number;
    scanLimit?: number;
    onMissing?: "throw" | "skip";
  } = {},
): Promise<ArchiveScan> {
  const received = sql<Date>`coalesce(${syslogEvents.ingestedAt}, ${syslogArchive.archivedAt})`;
  // Raw expressions get no column mapper, so timestamps are bound as ISO text and cast.
  const ts = (d: Date) => sql`${d.toISOString()}::timestamptz`;
  const where: (SQL | undefined)[] = [eq(syslogArchive.tenantId, tenantId)];
  if (opts.from) where.push(sql`${received} >= ${ts(opts.from)}`);
  if (opts.to) where.push(sql`${received} <= ${ts(opts.to)}`);
  if (opts.before) where.push(or(sql`${received} < ${ts(opts.before.at)}`, and(sql`${received} = ${ts(opts.before.at)}`, lt(syslogArchive.eventId, opts.before.id))));
  const scanLimit = opts.scanLimit ?? Number.POSITIVE_INFINITY;
  const limit = opts.limit ?? Number.POSITIVE_INFINITY;
  const rows = await withScope(systemScope(tenantId), (tx) => {
    const q = tx
      .select({ eventId: syslogArchive.eventId, region: syslogArchive.region, objectKey: syslogArchive.objectKey, receivedAt: received })
      .from(syslogArchive)
      .leftJoin(syslogEvents, and(eq(syslogEvents.id, syslogArchive.eventId), eq(syslogEvents.tenantId, tenantId)))
      .where(and(...where))
      .orderBy(desc(received), desc(syslogArchive.eventId));
    return Number.isFinite(scanLimit) ? q.limit(scanLimit + 1) : q;
  });
  const hits: ArchiveHit[] = [];
  let last: ArchiveKey | null = null;
  let missing = 0;
  let stoppedEarly = false;
  const scan = rows.slice(0, Number.isFinite(scanLimit) ? scanLimit : rows.length);
  for (const [i, row] of scan.entries()) {
    const receivedAt = new Date(row.receivedAt);
    last = { at: receivedAt, id: row.eventId };
    let line: string;
    try {
      line = await store.get(row.region, row.objectKey);
    } catch (err) {
      if (opts.onMissing !== "skip") throw err;
      missing += 1;
      continue;
    }
    if (!opts.match || opts.match(line)) hits.push({ eventId: row.eventId, region: row.region, line, receivedAt });
    if (hits.length >= limit) {
      stoppedEarly = i < rows.length - 1;
      break;
    }
  }
  return { hits, last, exhausted: !stoppedEarly && rows.length <= scan.length, missing };
}
