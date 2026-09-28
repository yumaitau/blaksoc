import "server-only";
import { cookies } from "next/headers";
import type { AccessContext } from "@/lib/auth/access";

export const WORKSPACE_COOKIE = "blaksoc_ws";

/**
 * The analyst's current customer workspace. "all" (default for SOC staff) spans every
 * tenant in scope. The cookie is only a preference: it is re-validated against the
 * caller's grants on every request.
 */
export async function currentWorkspace(ctx: AccessContext): Promise<{ tenantIds: string[]; tenant: AccessContext["tenants"][number] | null }> {
  const value = (await cookies()).get(WORKSPACE_COOKIE)?.value;
  const t = value && value !== "all" ? ctx.tenants.find((x) => x.id === value) : undefined;
  if (t) return { tenantIds: [t.id], tenant: t };
  const customers = ctx.tenants.filter((x) => x.kind === "customer");
  if (!ctx.isPlatform && customers.length === 1) return { tenantIds: [customers[0]!.id], tenant: customers[0]! };
  return { tenantIds: ctx.tenantIds, tenant: null };
}
