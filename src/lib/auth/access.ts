import { and, eq, inArray } from "drizzle-orm";
import { adminDb, db } from "@/db/client";
import { roleAssignments, roles, tenants } from "@/db/schema";
import { withScope, type DbScope } from "@/db/scope";
import { cobrandLine } from "@/lib/tenancy/brand";
import type { Permission } from "./permissions";

export type Grant = { roleKey: string; tenantId: string | null; permissions: Set<Permission> };

export type Principal = {
  userId: string;
  name: string;
  email: string;
  isBreakGlass: boolean;
};

export type TenantKind = "mssp" | "partner" | "customer";

export type TenantRef = {
  id: string;
  slug: string;
  name: string;
  kind: TenantKind;
  parentId?: string | null;
  brandName?: string | null;
  /** Partner name beside blakSOC. Null when this tenant has no partner. */
  cobrand?: string | null;
};

export type AccessContext = {
  principal: Principal;
  /** Holds a platform-scope role (Yuma IT staff). */
  isPlatform: boolean;
  grants: Grant[];
  /** Every tenant this principal can reach, including a partner's consented customers. */
  tenantIds: string[];
  tenants: TenantRef[];
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
  const none = ["00000000-0000-0000-0000-000000000000"];
  const columns = {
    id: tenants.id,
    slug: tenants.slug,
    name: tenants.name,
    kind: tenants.kind,
    status: tenants.status,
    parentId: tenants.parentId,
    brandName: tenants.brandName,
  };

  const tenantRows = await withScope({ tenantIds: directTenantIds, grantIds: directTenantIds, platform: isPlatform }, (tx) =>
    tx
      .select(columns)
      .from(tenants)
      .where(isPlatform ? eq(tenants.status, "active") : inArray(tenants.id, directTenantIds.length ? directTenantIds : none)),
  );
  const active = tenantRows.filter((t) => t.status === "active");
  const partnerIds = active.filter((t) => t.kind === "partner").map((t) => t.id);
  if (!isPlatform && partnerIds.length) {
    const children = await withScope({ tenantIds: partnerIds, grantIds: partnerIds, platform: false }, (tx) =>
      tx.select(columns).from(tenants).where(and(eq(tenants.status, "active"), inArray(tenants.parentId, partnerIds))),
    );
    for (const child of children) {
      if (!active.some((row) => row.id === child.id)) active.push(child);
    }
  }

  const byId = new Map(active.map((row) => [row.id, row]));
  const missingParents = [...new Set(active.map((row) => row.parentId).filter((id): id is string => !!id))].filter((id) => !byId.has(id));
  if (missingParents.length) {
    const parents = await adminDb().select(columns).from(tenants).where(inArray(tenants.id, missingParents));
    for (const parent of parents) byId.set(parent.id, parent);
  }
  const cobrandFor = (row: (typeof active)[number]) => {
    if (row.kind === "partner") return cobrandLine(row.name, row.brandName);
    if (!row.parentId) return null;
    const parent = byId.get(row.parentId);
    if (!parent || parent.kind !== "partner") return null;
    return cobrandLine(parent.name, parent.brandName);
  };

  return {
    principal,
    isPlatform,
    grants,
    tenantIds: active.map((t) => t.id),
    tenants: active.map((row) => {
      const { status: _status, ...tenant } = row;
      return { ...tenant, cobrand: cobrandFor(row) };
    }),
  };
}

export function permissionsFor(ctx: AccessContext, tenantId: string): Set<Permission> {
  const out = new Set<Permission>();
  if (!ctx.tenantIds.includes(tenantId)) return out;
  const parentId = ctx.tenants.find((t) => t.id === tenantId)?.parentId ?? null;
  for (const g of ctx.grants) {
    if (g.tenantId === null || g.tenantId === tenantId || (parentId !== null && g.tenantId === parentId)) {
      g.permissions.forEach((p) => out.add(p));
    }
  }
  return out;
}

/** Tenant ids on the role assignments themselves. Children are not included. */
export function directGrantIds(ctx: AccessContext): string[] {
  return [...new Set(ctx.grants.map((g) => g.tenantId).filter((t): t is string => !!t))];
}

/** RLS scope. Grant ids stay the direct assignments unless the caller is platform staff. */
export function dbScope(ctx: AccessContext, tenantIds: readonly string[], platform = false): DbScope {
  return {
    tenantIds,
    grantIds: ctx.isPlatform ? [...tenantIds] : directGrantIds(ctx),
    platform,
  };
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
  const tenantIds = tenantsWith(ctx, permission, requested);
  return {
    tenantIds,
    grantIds: ctx.isPlatform ? tenantIds : directGrantIds(ctx),
    platform: ctx.isPlatform && can(ctx, permission),
  };
}

/** System scope for worker jobs acting on one tenant. The id is a direct grant for that job only. */
export function systemScope(tenantId: string): DbScope {
  return { tenantIds: [tenantId], grantIds: [tenantId], platform: false };
}
