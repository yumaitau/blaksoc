import { AccessDenied, assertCan, scopeFor, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { withScope } from "@/db/scope";
import type { Tx } from "@/db/client";

export { AccessDenied };

/**
 * Run a read/write within the caller's RLS scope for `permission`, optionally narrowed
 * to requested tenants. Returns tenantIds so queries can also filter explicitly.
 */
export async function scoped<T>(
  ctx: AccessContext,
  permission: Permission,
  fn: (tx: Tx, tenantIds: string[]) => Promise<T>,
  requestedTenants?: readonly string[],
): Promise<T> {
  const scope = scopeFor(ctx, permission, requestedTenants);
  if (!scope.tenantIds.length && !scope.platform) throw new AccessDenied(`no tenant grants ${permission}`);
  return withScope(scope, (tx) => fn(tx, [...scope.tenantIds]));
}

/** Scope to exactly one tenant after verifying the permission there. */
export async function inTenant<T>(ctx: AccessContext, permission: Permission, tenantId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  assertCan(ctx, permission, tenantId);
  return withScope({ tenantIds: [tenantId], platform: false }, fn);
}

export const actor = (ctx: AccessContext) => ({ actorId: ctx.principal.userId, actorKind: "user" as const });
