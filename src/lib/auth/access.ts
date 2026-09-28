import { eq, inArray } from "drizzle-orm";
import { db } from "@/db/client";
import { roleAssignments, roles, tenants } from "@/db/schema";
import { withScope, type DbScope } from "@/db/scope";
import type { Permission } from "./permissions";

export type Grant = { roleKey: string; tenantId: string | null; permissions: Set<Permission> };

export type Principal = {
  userId: string;
  name: string;
  email: string;
  isBreakGlass: boolean;
};

export type AccessContext = {
  principal: Principal;
  /** Holds a platform-scope role (Yuma IT staff). */
  isPlatform: boolean;
  grants: Grant[];
  /** Every tenant this principal can reach. */
  tenantIds: string[];
  tenants: { id: string; slug: string; name: string; kind: "mssp" | "customer" }[];
};

export class AccessDenied extends Error {
  constructor(message = "forbidden") {
    super(message);
    this.name = "AccessDenied";
  }
}

export async function resolveAccess(principal: Principal): Promise<AccessContext> {
  // role_assignments/roles carry no RLS: they are how scope is established.
  const rows = await db()
    .select({ roleKey: roleAssignments.roleKey, tenantId: roleAssignments.tenantId, permissions: roles.permissions, scope: roles.scope })
    .from(roleAssignments)
    .innerJoin(roles, eq(roles.key, roleAssignments.roleKey))
    .where(eq(roleAssignments.userId, principal.userId));

  const grants: Grant[] = rows
    // A tenant-scope role without a tenant is a mis-assignment; it must never widen to platform scope.
    .filter((r) => r.scope === "platform" || r.tenantId)
    .map((r) => ({
      roleKey: r.roleKey,
      tenantId: r.scope === "platform" ? null : r.tenantId,
      permissions: new Set(r.permissions as Permission[]),
    }));

  const isPlatform = grants.some((g) => g.tenantId === null);
  const directTenantIds = [...new Set(grants.map((g) => g.tenantId).filter((t): t is string => !!t))];

  const tenantRows = await withScope({ tenantIds: directTenantIds, platform: isPlatform }, (tx) =>
    tx
      .select({ id: tenants.id, slug: tenants.slug, name: tenants.name, kind: tenants.kind, status: tenants.status })
      .from(tenants)
      .where(isPlatform ? eq(tenants.status, "active") : inArray(tenants.id, directTenantIds.length ? directTenantIds : ["00000000-0000-0000-0000-000000000000"])),
  );
  const active = tenantRows.filter((t) => t.status === "active");

  return {
    principal,
    isPlatform,
    grants,
    tenantIds: active.map((t) => t.id),
    tenants: active.map(({ status: _s, ...t }) => t),
  };
}

export function permissionsFor(ctx: AccessContext, tenantId: string): Set<Permission> {
  const out = new Set<Permission>();
  if (!ctx.tenantIds.includes(tenantId)) return out;
  for (const g of ctx.grants) {
    if (g.tenantId === null || g.tenantId === tenantId) g.permissions.forEach((p) => out.add(p));
  }
  return out;
}

export function can(ctx: AccessContext, permission: Permission, tenantId?: string): boolean {
  if (tenantId) return permissionsFor(ctx, tenantId).has(permission);
  return ctx.grants.some((g) => g.permissions.has(permission));
}

/** Tenants on which the principal holds `permission`, optionally narrowed to a requested subset. */
export function tenantsWith(ctx: AccessContext, permission: Permission, requested?: readonly string[]): string[] {
  const pool = requested?.length ? ctx.tenantIds.filter((t) => requested.includes(t)) : ctx.tenantIds;
  return pool.filter((t) => permissionsFor(ctx, t).has(permission));
}

export function assertCan(ctx: AccessContext, permission: Permission, tenantId?: string): void {
  if (!can(ctx, permission, tenantId)) throw new AccessDenied(`missing ${permission}`);
}

/** DB scope for a request: only the tenants that carry the needed permission. */
export function scopeFor(ctx: AccessContext, permission: Permission, requested?: readonly string[]): DbScope {
  return { tenantIds: tenantsWith(ctx, permission, requested), platform: ctx.isPlatform && can(ctx, permission) };
}

/** System scope for worker jobs acting on one tenant. */
export function systemScope(tenantId: string): DbScope {
  return { tenantIds: [tenantId], platform: false };
}
