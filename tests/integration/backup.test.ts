/**
 * Backup assurance against rows this file inserts. Calls createIntegration,
 * updateIntegration, syncVeeamBackups, instantiate, getAsset, and submitEssentialEight.
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { alerts, assets, backupStatus, integrations, tenants } from "@/db/schema";
import { systemScope, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { instantiate } from "@/lib/connectors/instances";
import { answerIds } from "@/lib/essential-eight/requirements";
import { syncVeeamBackups } from "@/lib/services/backup";
import { getAsset } from "@/lib/services/assets";
import { submitEssentialEight } from "@/lib/services/essential-eight";
import { createIntegration, updateIntegration } from "@/lib/services/integrations";

const created: string[] = [];

function staff(tenantId: string): AccessContext {
  const permissions = new Set<Permission>(["integration:manage", "asset:read", "report:generate"]);
  return {
    principal: { userId: "backup-staff", name: "Backup Admin", email: "backup@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "soc_manager", tenantId, permissions }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "backup", name: "Backup Clinic", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `bak-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Backup Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

function ago(hours: number) {
  return new Date(Date.now() - hours * 3_600_000).toISOString();
}

function systems(fixed: boolean) {
  return [
    { name: "File Server", hostname: "file.clinic.local", lastSuccessAt: ago(49), failedJobs: 2, restoreTestedAt: fixed ? ago(20) : null, immutable: fixed, offlineCopy: false },
    { name: "Archive Host", hostname: "archive.clinic.local", lastSuccessAt: ago(49), failedJobs: 1, restoreTestedAt: fixed ? ago(20) : null, immutable: false, offlineCopy: fixed },
    { name: "Mail Server", hostname: "mail.clinic.local", lastSuccessAt: ago(1), failedJobs: 0, restoreTestedAt: ago(5), immutable: true, offlineCopy: false },
  ];
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("backup assurance", () => {
  it("stores per-asset status, raises and clears stale alerts, and feeds Essential Eight", async () => {
    const tenant = await freshTenant();
    const other = await freshTenant();
    const ctx = staff(tenant.id);
    expect(await syncVeeamBackups(tenant.id)).toEqual({ protectedSystems: 0, staleAlerts: 0 });

    await expect(createIntegration(ctx, {
      tenantId: tenant.id,
      provider: "veeam",
      name: "Live Veeam",
      config: { mode: "live", staleHours: 24, systems: [{ name: "Ghost" }] },
      secrets: {},
    })).rejects.toThrow(/live Veeam/);
    expect(await adminDb().select().from(integrations).where(eq(integrations.tenantId, tenant.id))).toHaveLength(0);

    const id = await createIntegration(ctx, {
      tenantId: tenant.id,
      provider: "veeam",
      name: "Clinic Veeam",
      config: { mode: "fixture", staleHours: 48, systems: systems(false) },
      secrets: {},
    });

    const again = await syncVeeamBackups(tenant.id);
    expect(again).toEqual({ protectedSystems: 3, staleAlerts: 0 });

    const rows = await withScope(systemScope(tenant.id), (tx) => tx.select().from(backupStatus));
    expect(rows).toHaveLength(3);
    expect(await withScope(systemScope(other.id), (tx) => tx.select().from(backupStatus))).toEqual([]);

    const [fileAsset] = await adminDb().select().from(assets).where(and(eq(assets.tenantId, tenant.id), eq(assets.name, "File Server")));
    const detail = await getAsset(ctx, fileAsset!.id);
    expect(detail?.backup).toMatchObject({ failedJobs: 2, immutable: false, offlineCopy: false, stale: true, restoreTestedAt: null });
    expect(detail?.backup?.lastSuccessAt).toBeTruthy();

    const open = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.source, "veeam"), eq(alerts.status, "NEW")));
    expect(open.map((row) => row.externalId).sort()).toEqual(["stale:veeam:Archive Host", "stale:veeam:File Server"]);
    expect(open.every((row) => row.title.startsWith("Stale backup") && row.assetId)).toBe(true);

    const [saved] = await adminDb().select().from(integrations).where(eq(integrations.id, id));
    const inst = instantiate(saved!);
    expect(inst.kind).toBe("backup");
    if (inst.kind === "backup") await expect(inst.provider.health()).resolves.toMatchObject({ ok: true, detail: { mode: "fixture" } });

    const answers = Object.fromEntries(answerIds().map((key) => [key, "yes"]));
    const contradicted = await submitEssentialEight(ctx, tenant.id, { answers, owner: "Ava Chen", cadenceDays: 90 });
    const before = contradicted.result.ratings.find((row) => row.strategy === "regular_backups")!;
    expect(before.level).toBe(0);
    expect(before.telemetry).toContain("3 protected systems");
    expect(before.lines.find((row) => row.id === "bk-criticality")!.evidence.status).toBe("contradicts");
    expect(before.lines.find((row) => row.id === "bk-restore-tested")!.evidence.status).toBe("contradicts");
    expect(before.lines.find((row) => row.id === "bk-resilient")!.evidence.status).toBe("contradicts");
    expect(before.lines.find((row) => row.id === "bk-sync")!.evidence).toMatchObject({ status: "absent" });
    expect(before.lines.find((row) => row.id === "bk-sync")!.evidence.detail).toContain("does not report a common restore point");
    expect(before.lines.find((row) => row.id === "bk-unpriv-modify")!.evidence.detail).toContain("does not report who can open or delete");

    const [fileAlert] = open.filter((row) => row.externalId === "stale:veeam:File Server");
    await adminDb().update(alerts).set({ status: "FALSE_POSITIVE" }).where(eq(alerts.id, fileAlert!.id));
    await updateIntegration(ctx, id, { config: { mode: "fixture", staleHours: 72, systems: systems(false) } });

    const [fileAfter, archiveAfter] = await Promise.all([
      adminDb().select().from(alerts).where(eq(alerts.id, fileAlert!.id)),
      adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.externalId, "stale:veeam:Archive Host"))),
    ]);
    expect(fileAfter[0]?.status).toBe("FALSE_POSITIVE");
    expect(archiveAfter[0]?.status).toBe("RESOLVED");
    const refreshed = await getAsset(ctx, fileAsset!.id);
    expect(refreshed?.backup?.stale).toBe(false);
    expect(refreshed?.backup?.restoreTestedAt).toBeNull();

    await updateIntegration(ctx, id, { config: { mode: "fixture", staleHours: 72, systems: systems(true) } });
    const measured = await submitEssentialEight(ctx, tenant.id, { answers, owner: "Ava Chen", cadenceDays: 90 });
    const after = measured.result.ratings.find((row) => row.strategy === "regular_backups")!;
    expect(after.level).toBe(3);
    expect(after.lines.find((row) => row.id === "bk-criticality")!.evidence.status).toBe("measured");
    expect(after.lines.find((row) => row.id === "bk-restore-tested")!.evidence.status).toBe("measured");
    expect(after.lines.find((row) => row.id === "bk-resilient")!.evidence.status).toBe("measured");
    expect(after.lines.find((row) => row.id === "bk-admin-retention")!.evidence.status).toBe("absent");
    const restored = await getAsset(ctx, fileAsset!.id);
    expect(restored?.backup).toMatchObject({ stale: false, immutable: true, failedJobs: 2 });
    expect(restored?.backup?.restoreTestedAt).toBeTruthy();

    const live = await freshTenant();
    await adminDb().insert(integrations).values({
      tenantId: live.id,
      category: "backup",
      provider: "veeam",
      name: "Written live",
      config: { mode: "live", staleHours: 24, systems: [{ name: "Ghost" }] },
    });
    await expect(syncVeeamBackups(live.id)).rejects.toThrow(/live Veeam/);
    expect(await adminDb().select().from(assets).where(eq(assets.tenantId, live.id))).toEqual([]);
    expect(await adminDb().select().from(backupStatus).where(eq(backupStatus.tenantId, live.id))).toEqual([]);
  });
});
