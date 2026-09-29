/**
 * Self-assessment against rows this file inserts. The test calls submitEssentialEight
 * and reads the stored rating. It does not recompute maturity.
 */
import { randomUUID } from "node:crypto";
import { inflateSync } from "node:zlib";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { assets, auditLog, cveIntel, e8Assessments, e8Tasks, integrations, tenants, vulnerabilities } from "@/db/schema";
import { withScope } from "@/db/scope";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { answerIds } from "@/lib/essential-eight/requirements";
import { assessmentPdf, submitEssentialEight } from "@/lib/services/essential-eight";

function pdfPlain(bytes: Uint8Array) {
  const raw = Buffer.from(bytes);
  const latin = raw.toString("latin1");
  let out = "";
  const marker = /stream\r?\n/g;
  let match: RegExpExecArray | null;
  while ((match = marker.exec(latin))) {
    const start = match.index + match[0].length;
    const end = latin.indexOf("endstream", start);
    let chunk: Buffer = raw.subarray(start, end);
    if (chunk[chunk.length - 1] === 0x0a) chunk = chunk.subarray(0, -1);
    try {
      chunk = Buffer.from(inflateSync(chunk));
    } catch {
      // already plain
    }
    out += chunk.toString("latin1").replace(/<([0-9A-Fa-f\s]+)>/g, (_, hex: string) => Buffer.from(hex.replace(/\s/g, ""), "hex").toString("latin1"));
  }
  return out;
}

const created: string[] = [];
const cves: string[] = [];

function customer(tenantId: string, permissions: Set<Permission>): AccessContext {
  return {
    principal: { userId: "e8-customer", name: "Ess Admin", email: "e8@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "e8", name: "E8 Clinic", kind: "customer" }],
  };
}

function reader(tenantId: string) {
  return customer(tenantId, new Set(["portal:read", "report:generate", "report:read"]));
}

async function freshTenant() {
  const slug = `e8-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "E8 Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
  if (cves.length) await adminDb().delete(cveIntel).where(inArray(cveIntel.cve, cves));
});

describe("essential eight self-assessment", () => {
  it("lets telemetry override a yes, stores tasks, and exports the PDF", async () => {
    const tenant = await freshTenant();
    const cve = `CVE-2099-${randomUUID().slice(0, 8)}`;
    cves.push(cve);
    const assessedAt = new Date("2026-09-15T00:00:00.000Z");
    const db = adminDb();
    await db.insert(cveIntel).values({ cve, kev: true }).onConflictDoUpdate({ target: cveIntel.cve, set: { kev: true } });
    const [app] = await db.insert(assets).values({ tenantId: tenant.id, kind: "application", name: "Portal", exposure: "internet" }).returning();
    await db.insert(vulnerabilities).values({
      tenantId: tenant.id,
      assetId: app!.id,
      cve,
      packageName: "portal",
      status: "open",
      firstSeen: new Date(assessedAt.getTime() - 7 * 86_400_000),
    });
    await db.insert(assets).values([
      { tenantId: tenant.id, kind: "identity", name: "Admin", privileged: true, attributes: { mfa: false, internetAccess: true } },
      { tenantId: tenant.id, kind: "identity", name: "Staff", privileged: false, attributes: { mfa: true } },
    ]);
    await db.insert(integrations).values({
      tenantId: tenant.id,
      category: "endpoint",
      provider: "intune",
      name: "Intune",
      config: { officeMacros: { disabledWithoutNeed: false } },
    });

    const ctx = reader(tenant.id);
    const answers = Object.fromEntries(answerIds().map((id) => [id, "yes"]));
    const done = await submitEssentialEight(ctx, tenant.id, { answers, owner: "Ava Chen", cadenceDays: 90, assessedAt });
    const again = await submitEssentialEight(ctx, tenant.id, { answers, owner: "Ava Chen", cadenceDays: 90, assessedAt: new Date(assessedAt.getTime() + 86_400_000) });

    const patch = done.result.ratings.find((row) => row.strategy === "patch_applications")!;
    const patchLine = patch.lines.find((row) => row.id === "pa-online-48h")!;
    expect(patch.level).toBe(0);
    expect(patchLine.answer).toBe("yes");
    expect(patchLine.met).toBe(false);
    expect(patchLine.evidence.status).toBe("contradicts");
    expect(patchLine.evidence.detail).toContain(cve);

    const mfa = done.result.ratings.find((row) => row.strategy === "mfa")!;
    expect(mfa.level).toBe(0);
    expect(mfa.lines.find((row) => row.id === "mfa-own-sensitive")).toMatchObject({ answer: "yes", met: false, evidence: { status: "contradicts" } });

    const admin = done.result.ratings.find((row) => row.strategy === "restrict_admin")!;
    expect(admin.level).toBe(0);
    expect(admin.telemetry).toContain("1 privileged identity of 2");
    expect(admin.lines.find((row) => row.id === "ra-no-internet")!.evidence.status).toBe("contradicts");

    const macros = done.result.ratings.find((row) => row.strategy === "office_macros")!;
    expect(macros.level).toBe(0);
    expect(macros.lines.find((row) => row.id === "om-disabled")!.evidence.status).toBe("contradicts");

    const backups = done.result.ratings.find((row) => row.strategy === "regular_backups")!;
    expect(backups.level).toBe(3);
    expect(backups.lines.find((row) => row.id === "bk-restore-tested")!.evidence.detail).toContain("not connected");

    expect(done.result.disclaimer).toContain("not an ACSC-endorsed audit");
    expect(done.result.trend.regular_backups).toBe("first");
    expect(again.result.previous?.levels.regular_backups).toBe(3);
    expect(again.result.previous?.levels.patch_applications).toBe(0);
    expect(again.result.trend.regular_backups).toBe("same");
    expect(again.result.nextDue.slice(0, 10)).toBe("2026-12-15");

    const due = new Date(assessedAt.getTime() + 14 * 86_400_000).toISOString();
    for (const id of ["pa-online-48h", "mfa-own-sensitive", "ra-no-internet", "om-disabled"]) {
      expect(done.result.remediation.find((item) => item.requirementId === id)).toMatchObject({ owner: "Ava Chen", dueAt: due, priority: 1 });
    }
    expect(done.result.remediation.some((item) => item.requirementId === "bk-restore-tested")).toBe(false);

    const tasks = await db.select().from(e8Tasks).where(eq(e8Tasks.assessmentId, done.id));
    expect(tasks).toHaveLength(done.result.remediation.length);
    expect(tasks.find((row) => row.requirementId === "pa-online-48h")).toMatchObject({ owner: "Ava Chen", status: "open" });

    const pdf = await assessmentPdf(ctx, tenant.id, done.id);
    expect(Buffer.from(pdf.subarray(0, 4)).toString()).toBe("%PDF");
    const plain = pdfPlain(pdf);
    expect(plain).toContain("ACSC-endorsed");
    expect(plain).toContain("Ava Chen");
    expect(plain).toContain(cve);

    const [audit] = await db.select().from(auditLog).where(and(eq(auditLog.tenantId, tenant.id), eq(auditLog.action, "e8.assess"), eq(auditLog.targetId, done.id)));
    expect(audit).toBeTruthy();

    const hidden = await withScope({ tenantIds: [], platform: true }, (tx) => tx.select().from(e8Assessments).where(eq(e8Assessments.tenantId, tenant.id)));
    expect(hidden).toEqual([]);

    const denied = customer(tenant.id, new Set(["portal:read"]));
    await expect(submitEssentialEight(denied, tenant.id, { answers, owner: "Ava Chen", cadenceDays: 90, assessedAt })).rejects.toBeInstanceOf(AccessDenied);
  });
});
