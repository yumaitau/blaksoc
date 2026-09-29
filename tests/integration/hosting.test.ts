import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { integrations, syslogArchive, syslogEvents, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { systemScope } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { eventProvider } from "@/lib/connectors/instances";
import { FileArchiveStore } from "@/lib/hosting/store";
import { acceptSyslog, archiveColdForTenant, createSyslogSource, restoreArchive, searchArchive } from "@/lib/services/syslog";
import { SYSLOG_LINES } from "../fixtures/syslog";

const created: string[] = [];
const roots: string[] = [];

function staff(tenantId: string): AccessContext {
  const permissions = new Set<Permission>(["integration:manage"]);
  return {
    principal: { userId: "hosting-staff", name: "Net Admin", email: "net@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "hosting", name: "Creek Clinic", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `host-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Creek Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
});

describe("archive restore", () => {
  it("archives to an Australian object, searches that object, and restores it onto the hot tier", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "blaksoc-archive-"));
    roots.push(root);
    const store = new FileArchiveStore(root);
    const tenant = await freshTenant();
    const other = await freshTenant();
    const source = await createSyslogSource(staff(tenant.id), tenant.id, { name: "Old firewall" });
    const otherSource = await createSyslogSource(staff(other.id), other.id, { name: "Other firewall" });
    const old = new Date(Date.now() - 31 * 86_400_000);
    await acceptOld(source.token, SYSLOG_LINES.draytek, old);
    await acceptOld(otherSource.token, SYSLOG_LINES.sophos, old);

    await expect(archiveColdForTenant(tenant.id, new Date(), "eu-central-1", store)).rejects.toThrow(/Australia/);
    expect(await store.list("ap-southeast-4", `syslog/${tenant.id}/`)).toEqual([]);

    expect(await archiveColdForTenant(tenant.id, new Date(), "ap-southeast-4", store)).toBe(1);
    expect(await archiveColdForTenant(other.id, new Date(), "ap-southeast-2", store)).toBe(1);

    const [integration] = await adminDb().select().from(integrations).where(eq(integrations.tenantId, tenant.id));
    expect((await eventProvider(integration!).getAlerts({ limit: 10 })).alerts).toHaveLength(0);

    const [copy] = await withScope(systemScope(tenant.id), (tx) => tx.select().from(syslogArchive));
    expect(copy).toMatchObject({ region: "ap-southeast-4", body: SYSLOG_LINES.draytek });
    expect(await store.get(copy!.region, copy!.objectKey)).toBe(SYSLOG_LINES.draytek);

    await withScope(systemScope(tenant.id), (tx) => tx.update(syslogArchive).set({ body: "tampered" }).where(eq(syslogArchive.id, copy!.id)));
    const found = await searchArchive(tenant.id, "DrayTek", store);
    expect(found).toEqual([{ eventId: copy!.eventId, region: "ap-southeast-4", line: SYSLOG_LINES.draytek }]);
    expect(await searchArchive(other.id, "DrayTek", store)).toEqual([]);

    await rm(path.join(root, copy!.region, copy!.objectKey));
    await expect(restoreArchive(tenant.id, copy!.eventId, store)).rejects.toThrow(/missing/);
    expect((await eventProvider(integration!).getAlerts({ limit: 10 })).alerts).toHaveLength(0);

    await store.put(copy!.region, copy!.objectKey, SYSLOG_LINES.draytek);
    await withScope(systemScope(tenant.id), (tx) => tx.update(syslogEvents).set({ line: "gone" }).where(eq(syslogEvents.id, copy!.eventId)));
    await restoreArchive(tenant.id, copy!.eventId, store);
    const hot = (await eventProvider(integration!).getAlerts({ limit: 10 })).alerts;
    expect(hot.map((row) => row.raw.line)).toEqual([SYSLOG_LINES.draytek]);
  });
});

async function acceptOld(token: string, body: string, now: Date) {
  await acceptSyslog({ token, sourceIp: "", body, now });
}
