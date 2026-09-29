/**
 * Customer admins consent to a practice campaign and set its time.
 * The board sees counts only. Named clicks stay on the admin coaching list.
 */
import { randomUUID } from "node:crypto";
import { inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { tenants } from "@/db/schema";
import { withScope } from "@/db/scope";
import type { AccessContext } from "@/lib/auth/access";
import { systemScope } from "@/lib/auth/access";
import { buildReport } from "@/lib/reports/generate";
import { AwarenessError, listCoaching, recordPracticeClick, scheduleCampaign } from "@/lib/services/awareness";
import { AccessDenied } from "@/lib/services/common";

const created: string[] = [];

function admin(tenantId: string, slug: string): AccessContext {
  return {
    principal: { userId: "aware-admin", name: "Clinic Admin", email: "aware@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId, permissions: new Set(["user:manage"]) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug, name: "River Clinic", kind: "customer" }],
  };
}

function reporter(tenantId: string, slug: string): AccessContext {
  return {
    ...admin(tenantId, slug),
    principal: { userId: "aware-reader", name: "Reader", email: "reader@example.invalid", isBreakGlass: false },
    grants: [{ roleKey: "customer_security", tenantId, permissions: new Set(["report:generate"]) }],
  };
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("awareness practice campaign", () => {
  it("lets the customer admin schedule and keeps names off the board", async () => {
    const slug = `aware-${randomUUID().slice(0, 8)}`;
    const [tenant] = await adminDb().insert(tenants).values({ slug, name: "River Clinic", kind: "customer" }).returning();
    created.push(tenant!.id);
    const ctx = admin(tenant!.id, slug);
    const when = new Date("2026-06-01T00:00:00.000Z");

    await expect(scheduleCampaign(reporter(tenant!.id, slug), tenant!.id, { consented: true, scheduledAt: when })).rejects.toBeInstanceOf(AccessDenied);
    await expect(scheduleCampaign(ctx, tenant!.id, { consented: false, scheduledAt: when })).rejects.toBeInstanceOf(AwarenessError);

    const campaign = await scheduleCampaign(ctx, tenant!.id, { consented: true, scheduledAt: when });
    await recordPracticeClick(ctx, tenant!.id, campaign.id, "Sam Cole", when);
    await recordPracticeClick(ctx, tenant!.id, campaign.id, "Sam Cole", when);
    await recordPracticeClick(ctx, tenant!.id, campaign.id, "Alex Ng", when);

    const coaching = await listCoaching(ctx, tenant!.id);
    expect(coaching).toEqual([{ person: "Sam Cole", clicks: 2 }]);

    const board = await withScope(systemScope(tenant!.id), (tx) => buildReport(tx, tenant!.id, "board_summary", { end: when }));
    const section = board.sections.find((item) => item.heading === "Awareness");
    expect(section?.body).toBe("One practice send was scheduled. 3 practice clicks were recorded. No person is named here.");
    const packed = JSON.stringify(board.sections);
    expect(packed).not.toContain("Sam Cole");
    expect(packed).not.toContain("Alex Ng");

    const other = admin(randomUUID(), "other");
    await expect(scheduleCampaign(other, tenant!.id, { consented: true, scheduledAt: when })).rejects.toBeInstanceOf(AccessDenied);
  });
});
