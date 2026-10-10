import { sql, eq } from "drizzle-orm";
import { dashboardLayouts } from "@/db/schema";
import { withScope } from "@/db/scope";
import type { Tx } from "@/db/client";
import { AccessDenied, assertCan, dbScope, type AccessContext } from "@/lib/auth/access";
import { defaultLayout, layoutForSave, normalizeLayout, type DashboardWidget } from "@/lib/dashboard/layout";

async function withOwnLayout<T>(ctx: AccessContext, userId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  return withScope(dbScope(ctx, ctx.tenantIds, true), async (tx) => {
    // Own-row policy compares user_id to this setting. Unset, the row is invisible.
    await tx.execute(sql`select set_config('app.user_id', ${userId}, true)`);
    return fn(tx);
  });
}

export async function readDashboardLayout(ctx: AccessContext): Promise<DashboardWidget[]> {
  assertCan(ctx, "dashboard:read");
  if (!ctx.isPlatform || ctx.principal.kind === "service") return defaultLayout();
  const userId = ctx.principal.userId;
  const rows = await withOwnLayout(ctx, userId, (tx) =>
    tx.select({ widgets: dashboardLayouts.widgets }).from(dashboardLayouts).where(eq(dashboardLayouts.userId, userId)),
  );
  return normalizeLayout(rows[0]?.widgets);
}

export async function writeDashboardLayout(ctx: AccessContext, input: unknown): Promise<void> {
  assertCan(ctx, "dashboard:read");
  if (!ctx.isPlatform) throw new AccessDenied("missing dashboard:read");
  if (ctx.principal.kind === "service") throw new AccessDenied("a service identity has no dashboard layout");
  const widgets = layoutForSave(input);
  const userId = ctx.principal.userId;
  const updatedAt = new Date();
  await withOwnLayout(ctx, userId, (tx) =>
    tx
      .insert(dashboardLayouts)
      .values({ userId, widgets, updatedAt })
      .onConflictDoUpdate({ target: dashboardLayouts.userId, set: { widgets, updatedAt } }),
  );
}
