import { createHash, randomBytes } from "node:crypto";
import { and, eq, lt } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { integrations, syslogArchive, syslogEvents, syslogSources } from "@/db/schema";
import { audit } from "@/lib/audit";
import type { AccessContext } from "@/lib/auth/access";
import { systemScope } from "@/lib/auth/access";
import { connectorDef } from "@/lib/connectors/registry";
import { parseSyslog } from "@/lib/syslog/parse";
import { defaultArchiveStore, type ArchiveStore } from "@/lib/hosting/store";
import { archiveKey, assertAuRegion, SYSLOG_HOT_MS } from "@/lib/syslog/retain";
import { assertDemoOnly } from "@/lib/training/isolation";
import { actor, inTenant } from "./common";

export class SyslogError extends Error {
  readonly code: "token" | "source-ip" | "name" | "ip";
  constructor(code: "token" | "source-ip" | "name" | "ip") {
    super(code);
    this.name = "SyslogError";
    this.code = code;
  }
}

export function ipv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Create the bearer token and the per-tenant syslog integration the worker polls. */
export async function createSyslogSource(ctx: AccessContext, tenantId: string, input: { name: string; allowIps?: string[] }): Promise<{ id: string; token: string }> {
  const name = input.name.trim();
  if (name.length < 1 || name.length > 80) throw new SyslogError("name");
  const allowIps = input.allowIps ?? [];
  if (allowIps.some((ip) => !ipv4(ip))) throw new SyslogError("ip");
  const token = randomBytes(32).toString("base64url");
  const tokenHash = hashToken(token);
  const id = await inTenant(ctx, "integration:manage", tenantId, async (tx) => {
    await assertDemoOnly(tx, tenantId, "syslog");
    const [source] = await tx.insert(syslogSources).values({ tenantId, name, tokenHash, allowIps }).returning({ id: syslogSources.id });
    const [existing] = await tx.select({ id: integrations.id }).from(integrations).where(and(eq(integrations.tenantId, tenantId), eq(integrations.provider, "syslog")));
    if (!existing) {
      const def = connectorDef("syslog");
      if (!def) throw new Error("syslog connector is missing");
      await tx.insert(integrations).values({
        tenantId,
        category: def.category,
        provider: def.provider,
        name: "Firewall syslog",
        config: def.config.parse({ region: "ap-southeast-2", tenantId }),
        status: "healthy",
        permissions: def.remotePermissions,
      });
    }
    await audit(tx, { ...actor(ctx), tenantId, action: "syslog.source_create", targetType: "syslog_source", targetId: source!.id, detail: { name, allowIps } });
    return source!.id;
  });
  return { id, token };
}

const MAX_LINES = 100;
const MAX_LINE = 8000;

/** Store lines for the tenant that owns the token. Unknown shapes are counted and dropped. */
export async function acceptSyslog(input: { token: string; sourceIp: string; body: string; now?: Date }): Promise<{ accepted: number; rejected: number }> {
  const now = input.now ?? new Date();
  const [source] = await systemDb().select().from(syslogSources).where(eq(syslogSources.tokenHash, hashToken(input.token)));
  if (!source) throw new SyslogError("token");
  if (source.allowIps.length && !source.allowIps.includes(input.sourceIp)) throw new SyslogError("source-ip");
  const all = input.body.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const lines = all.slice(0, MAX_LINES);
  let rejected = all.length - lines.length;
  let accepted = 0;
  const retainUntil = new Date(now.getTime() + SYSLOG_HOT_MS);
  await withScope(systemScope(source.tenantId), async (tx) => {
    for (const line of lines) {
      const parsed = line.length <= MAX_LINE ? parseSyslog(line) : null;
      if (!parsed) {
        rejected += 1;
        continue;
      }
      await tx.insert(syslogEvents).values({
        tenantId: source.tenantId,
        sourceId: source.id,
        vendor: parsed.vendor,
        action: parsed.action,
        line,
        byteLen: Buffer.byteLength(line),
        tier: "hot",
        ingestedAt: now,
        retainUntil,
      });
      accepted += 1;
    }
  });
  return { accepted, rejected };
}

async function regionFor(tenantId: string): Promise<string> {
  const [row] = await systemDb().select({ config: integrations.config }).from(integrations).where(and(eq(integrations.tenantId, tenantId), eq(integrations.provider, "syslog")));
  const region = row?.config.region;
  return typeof region === "string" ? region : "ap-southeast-2";
}

/** Copy lines older than 30 days into the AU object store and take them out of the hot query. */
export async function archiveColdForTenant(tenantId: string, now = new Date(), region?: string, store: ArchiveStore = defaultArchiveStore()): Promise<number> {
  const chosen = region ?? (await regionFor(tenantId));
  assertAuRegion(chosen);
  const cutoff = new Date(now.getTime() - SYSLOG_HOT_MS);
  return withScope(systemScope(tenantId), async (tx) => {
    const due = await tx
      .select()
      .from(syslogEvents)
      .where(and(eq(syslogEvents.tenantId, tenantId), eq(syslogEvents.tier, "hot"), lt(syslogEvents.ingestedAt, cutoff)));
    for (const row of due) {
      const objectKey = archiveKey(tenantId, row.id);
      await store.put(chosen, objectKey, row.line);
      await tx.insert(syslogArchive).values({ tenantId, eventId: row.id, region: chosen, objectKey, body: row.line }).onConflictDoNothing();
      await tx.update(syslogEvents).set({ tier: "cold" }).where(eq(syslogEvents.id, row.id));
    }
    return due.length;
  });
}

/** Match archived lines by reading the object store. The Postgres body column is not the source. */
export async function searchArchive(tenantId: string, query: string, store: ArchiveStore = defaultArchiveStore()): Promise<{ eventId: string; region: string; line: string }[]> {
  const rows = await withScope(systemScope(tenantId), (tx) => tx.select().from(syslogArchive).where(eq(syslogArchive.tenantId, tenantId)));
  const found: { eventId: string; region: string; line: string }[] = [];
  for (const row of rows) {
    const line = await store.get(row.region, row.objectKey);
    if (query.length === 0 || line.includes(query)) found.push({ eventId: row.eventId, region: row.region, line });
  }
  return found;
}

/** Put the archived object back on the hot event. */
export async function restoreArchive(tenantId: string, eventId: string, store: ArchiveStore = defaultArchiveStore()): Promise<void> {
  const [row] = await withScope(systemScope(tenantId), (tx) =>
    tx.select().from(syslogArchive).where(and(eq(syslogArchive.tenantId, tenantId), eq(syslogArchive.eventId, eventId))),
  );
  if (!row) throw new Error("archive object missing");
  const line = await store.get(row.region, row.objectKey);
  await withScope(systemScope(tenantId), async (tx) => {
    await tx.update(syslogEvents).set({ tier: "hot", line, byteLen: Buffer.byteLength(line) }).where(and(eq(syslogEvents.id, eventId), eq(syslogEvents.tenantId, tenantId)));
  });
}

/** Worker sweep. Tests call archiveColdForTenant for one tenant instead. */
export async function archiveDueSyslog(now = new Date()): Promise<{ archived: number; failed: number }> {
  const cutoff = new Date(now.getTime() - SYSLOG_HOT_MS);
  const rows = await systemDb()
    .select({ tenantId: syslogEvents.tenantId })
    .from(syslogEvents)
    .where(and(eq(syslogEvents.tier, "hot"), lt(syslogEvents.ingestedAt, cutoff)))
    .groupBy(syslogEvents.tenantId);
  let archived = 0;
  let failed = 0;
  for (const row of rows) {
    try {
      archived += await archiveColdForTenant(row.tenantId, now);
    } catch {
      failed += 1;
    }
  }
  return { archived, failed };
}

/** Stamp the integration owner onto syslog config so a pasted tenant id cannot reroute lines. */
export function stampSyslogTenant(provider: string, config: Record<string, unknown>, tenantId: string | null): Record<string, unknown> {
  if (provider !== "syslog") return config;
  if (!tenantId) throw new Error("syslog ingest belongs to one tenant");
  return { ...config, tenantId };
}
