import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it, vi } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, integrations, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { SyslogProvider } from "@/lib/providers/syslog";
import { queue, QUEUES } from "@/lib/queue";
import { redis } from "@/lib/redis";
import { acceptSyslog, createSyslogSource } from "@/lib/services/syslog";
import { cursorKey, pollIntegration } from "@/worker/jobs/ingest";
import { ensureSchedules, SCHEDULES } from "@/worker/schedules";
import { SYSLOG_LINES } from "../fixtures/syslog";

const created: string[] = [];
const log = () => {};
const essentials = () => "essentials" as const;

function staff(tenantId: string): AccessContext {
  return {
    principal: { userId: "redis-loss", name: "Net Admin", email: "net@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions: new Set<Permission>(["integration:manage"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "redis-loss", name: "Creek Clinic", kind: "customer" }],
  };
}

async function syslogTenant() {
  const [tenant] = await adminDb().insert(tenants).values({ slug: `redis-${randomUUID().slice(0, 8)}`, name: "Creek Clinic", kind: "customer" }).returning();
  created.push(tenant!.id);
  const source = await createSyslogSource(staff(tenant!.id), tenant!.id, { name: "Front firewall" });
  const row = async () => (await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, tenant!.id), eq(integrations.provider, "syslog"))))[0]!;
  const alertLines = async () =>
    (await adminDb().select({ raw: alerts.raw }).from(alerts).where(and(eq(alerts.tenantId, tenant!.id), eq(alerts.source, "syslog")))).map((a) => (a.raw as { line: string }).line).sort();
  return { tenant: tenant!, token: source.token, row, alertLines };
}

afterAll(async () => {
  vi.restoreAllMocks();
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
  await Promise.all(Object.values(QUEUES).map((name) => queue(name).close()));
  await redis().quit();
});

describe("Redis loss", () => {
  it("keeps the alert cursor in Postgres, so a flush neither replays nor skips alerts", async () => {
    const t = await syslogTenant();
    await acceptSyslog({ token: t.token, sourceIp: "", body: `${SYSLOG_LINES.fortinet}\n${SYSLOG_LINES.sophos}` });
    expect(await pollIntegration(await t.row(), essentials, log)).toBe(2);
    const saved = (await t.row()).pollCursor;
    expect(saved).toBeTruthy();
    expect(await redis().get(cursorKey((await t.row()).id))).toBe(saved);

    await redis().flushdb();
    await acceptSyslog({ token: t.token, sourceIp: "", body: SYSLOG_LINES.mikrotik });
    const reads = vi.spyOn(SyslogProvider.prototype, "getAlerts");
    expect(await pollIntegration(await t.row(), essentials, log)).toBe(1);
    // Resumed from the Postgres cursor: only the line that arrived after it was read.
    expect(reads.mock.calls[0]![0].afterCursor).toBe(saved);
    expect((await reads.mock.results[0]!.value).alerts.map((a: { raw: { line: string } }) => a.raw.line)).toEqual([SYSLOG_LINES.mikrotik]);
    reads.mockRestore();
    expect(await t.alertLines()).toEqual([SYSLOG_LINES.fortinet, SYSLOG_LINES.mikrotik, SYSLOG_LINES.sophos].sort());
    // The cache is rebuilt from Postgres.
    expect(await redis().get(cursorKey((await t.row()).id))).toBe((await t.row()).pollCursor);
  });

  it("adopts a cursor that only Redis has, and dedupes a replay when neither has one", async () => {
    const t = await syslogTenant();
    await acceptSyslog({ token: t.token, sourceIp: "", body: `${SYSLOG_LINES.fortinet}\n${SYSLOG_LINES.draytek}` });
    expect(await pollIntegration(await t.row(), essentials, log)).toBe(2);
    const id = (await t.row()).id;
    const cursor = (await t.row()).pollCursor!;

    // A row written by an older worker: cursor in Redis only.
    await adminDb().update(integrations).set({ pollCursor: null }).where(eq(integrations.id, id));
    await redis().set(cursorKey(id), cursor);
    const reads = vi.spyOn(SyslogProvider.prototype, "getAlerts");
    expect(await pollIntegration(await t.row(), essentials, log)).toBe(0);
    expect(reads.mock.calls[0]![0].afterCursor).toBe(cursor);
    expect((await t.row()).pollCursor).toBe(cursor);

    // Both copies lost: the provider replays from its start, and the external-id dedupe holds.
    await adminDb().update(integrations).set({ pollCursor: null }).where(eq(integrations.id, id));
    await redis().flushdb();
    reads.mockClear();
    expect(await pollIntegration(await t.row(), essentials, log)).toBe(0);
    expect(reads.mock.calls[0]![0].afterCursor).toBeUndefined();
    reads.mockRestore();
    expect(await t.alertLines()).toEqual([SYSLOG_LINES.draytek, SYSLOG_LINES.fortinet].sort());
  });

  it("recreates the worker schedulers a flush removed and leaves existing ones alone", async () => {
    await ensureSchedules(true);
    expect(await ensureSchedules()).toEqual([]);
    await redis().flushdb();
    const ids = SCHEDULES.map((s) => `${s.queue}:${s.name}`);
    expect(await ensureSchedules()).toEqual(ids);
    for (const s of SCHEDULES) expect(await queue(s.queue).getJobScheduler(`${s.queue}:${s.name}`)).toMatchObject({ every: s.every });
    expect(await ensureSchedules()).toEqual([]);
    for (const s of SCHEDULES) await queue(s.queue).removeJobScheduler(`${s.queue}:${s.name}`);
  });
});
