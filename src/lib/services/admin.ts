import { and, desc, eq, gte, ilike, inArray, isNull, lt, or, sql } from "drizzle-orm";
import { db, systemDb, type Tx } from "@/db/client";
import { auditLog, DEFAULT_TENANT_SETTINGS, integrations, integrationTenantLinks, roleAssignments, roles, serviceIdentities, sites, ssoProvider, tenants, user, type TenantSettings } from "@/db/schema";
import { withScope } from "@/db/scope";
import { assertCan, can, dbScope, systemScope, tenantRoleGrantDenial, type AccessContext } from "@/lib/auth/access";
import { googleEndpoints } from "@/lib/auth/sso-policy";
import { audit, verifyAuditChain } from "@/lib/audit";
import { auditNameIds } from "@/lib/audit/describe";
import type { AuditFilters } from "@/lib/audit/filters";
import { TrainingIsolationError } from "@/lib/training/isolation";
import { actor, AccessDenied, scoped } from "./common";
import { notifyStewards, STEWARD_ROLE, userHoldsPlatformRole } from "./governance";

const platformOnly = (ctx: AccessContext, perm: "tenant:manage" | "user:manage" | "settings:manage" | "audit:read") => {
  if (!ctx.isPlatform || !can(ctx, perm)) throw new AccessDenied(`platform ${perm} required`);
};

export async function listTenants(ctx: AccessContext) {
  return withScope(dbScope(ctx, ctx.tenantIds, ctx.isPlatform), (tx) => tx.select().from(tenants).where(inArray(tenants.id, ctx.tenantIds.length ? ctx.tenantIds : ["00000000-0000-0000-0000-000000000000"])).orderBy(tenants.kind, tenants.name));
}

export async function createTenant(ctx: AccessContext, input: { name: string; slug: string; sectors: string[]; deploymentMode: "shared" | "dedicated" }) {
  platformOnly(ctx, "tenant:manage");
  if (!/^[a-z0-9-]{2,40}$/.test(input.slug)) throw new Error("slug must be lowercase letters, digits, hyphens");
  return withScope({ tenantIds: [], platform: true }, async (tx) => {
    const [t] = await tx.insert(tenants).values({ ...input, kind: "customer", settings: DEFAULT_TENANT_SETTINGS }).returning();
    await audit(tx, { ...actor(ctx), tenantId: null, action: "tenant.create", targetType: "tenant", targetId: t!.id, detail: input });
    return t!;
  });
}

export async function updateTenantSettings(ctx: AccessContext, tenantId: string, patch: Partial<TenantSettings>) {
  assertCan(ctx, "settings:manage", tenantId);
  // Auto-containment is a platform decision: it lets playbooks isolate endpoints without a human gate.
  if (patch.autoContainment !== undefined && !(ctx.isPlatform && can(ctx, "tenant:manage"))) throw new AccessDenied("only platform administrators may change auto-containment");
  if (patch.training === true) {
    // Shared platform integrations are invisible to tenant scope, so read the links as the system role.
    const owned = await systemDb().select({ provider: integrations.provider }).from(integrations).where(eq(integrations.tenantId, tenantId));
    const linked = await systemDb()
      .select({ provider: integrations.provider })
      .from(integrationTenantLinks)
      .innerJoin(integrations, eq(integrations.id, integrationTenantLinks.integrationId))
      .where(eq(integrationTenantLinks.tenantId, tenantId));
    if ([...owned, ...linked].some((row) => row.provider !== "demo")) throw new TrainingIsolationError("real");
  }
  // The caller's own scope. Platform staff write through platform_write; a partner admin writes its
  // own tenancy or a consented customer through the partner update policies (005_rls.sql).
  return withScope(dbScope(ctx, [tenantId], ctx.isPlatform && can(ctx, "settings:manage")), async (tx) => {
    const [t] = await tx.select().from(tenants).where(eq(tenants.id, tenantId));
    if (!t) throw new AccessDenied();
    const settings = { ...t.settings, ...patch, sharing: { ...t.settings.sharing, ...patch.sharing }, ai: { ...t.settings.ai, ...patch.ai }, slaMinutes: { ...t.settings.slaMinutes, ...patch.slaMinutes } };
    // RLS decides whether this caller may write the row; zero rows means it may not, so do not audit a change that did not happen.
    const updated = await tx.update(tenants).set({ settings }).where(eq(tenants.id, tenantId)).returning({ id: tenants.id });
    if (!updated.length) throw new AccessDenied("tenant settings cannot be changed from this role; ask a platform administrator");
    await audit(tx, { ...actor(ctx), tenantId, action: "tenant.settings", targetType: "tenant", targetId: tenantId, detail: { before: t.settings, after: settings } });
    return settings;
  });
}

export async function createSite(ctx: AccessContext, tenantId: string, name: string, location?: string, link: "standard" | "low" = "standard") {
  assertCan(ctx, "asset:write", tenantId);
  return withScope(dbScope(ctx, [tenantId]), (tx) => tx.insert(sites).values({ tenantId, name, location, bandwidthProfile: link }).returning());
}

/** Users visible to the caller: platform staff see all; customer admins see their tenant's users. */
export async function listUsers(ctx: AccessContext) {
  if (!can(ctx, "user:manage")) throw new AccessDenied();
  const scopeTenants = ctx.tenantIds.filter((t) => can(ctx, "user:manage", t));
  const assignments = await db()
    .select({ userId: roleAssignments.userId, id: roleAssignments.id, roleKey: roleAssignments.roleKey, roleName: roles.name, tenantId: roleAssignments.tenantId })
    .from(roleAssignments)
    .innerJoin(roles, eq(roles.key, roleAssignments.roleKey))
    .where(ctx.isPlatform ? undefined : inArray(roleAssignments.tenantId, scopeTenants));
  const userIds = [...new Set(assignments.map((a) => a.userId))];
  const users = ctx.isPlatform
    ? await db().select({ id: user.id, name: user.name, email: user.email, isBreakGlass: user.isBreakGlass, disabled: user.disabled, twoFactorEnabled: user.twoFactorEnabled, createdAt: user.createdAt }).from(user).orderBy(user.name)
    : userIds.length ? await db().select({ id: user.id, name: user.name, email: user.email, isBreakGlass: user.isBreakGlass, disabled: user.disabled, twoFactorEnabled: user.twoFactorEnabled, createdAt: user.createdAt }).from(user).where(inArray(user.id, userIds)) : [];
  return users.map((u) => ({ ...u, assignments: assignments.filter((a) => a.userId === u.id) }));
}

export async function listRoles() {
  return db().select().from(roles).orderBy(roles.scope, roles.name);
}

export async function assignRole(ctx: AccessContext, input: { userId: string; roleKey: string; tenantId: string | null }) {
  const [role] = await db().select().from(roles).where(eq(roles.key, input.roleKey));
  if (!role) throw new Error("unknown role");
  if (role.scope === "platform") {
    platformOnly(ctx, "user:manage");
    if (input.tenantId) throw new Error("platform roles are not tenant-bound");
  } else {
    if (!input.tenantId) throw new Error("tenant roles require a tenant");
    await assertTenantRoleGrant(ctx, role, input.tenantId);
  }
  // Stewards speak for the organisation. Yuma IT staff must never approve their own access to it.
  if (role.key === STEWARD_ROLE && (await userHoldsPlatformRole(input.userId))) throw new Error("platform staff cannot be data stewards");
  if (role.scope === "platform" && (await db().select({ id: roleAssignments.id }).from(roleAssignments).where(and(eq(roleAssignments.userId, input.userId), eq(roleAssignments.roleKey, STEWARD_ROLE))).limit(1)).length) {
    throw new Error("data stewards cannot hold platform roles");
  }
  await db().insert(roleAssignments).values({ userId: input.userId, roleKey: input.roleKey, tenantId: input.tenantId, createdBy: ctx.principal.userId }).onConflictDoNothing();
  await withScope({ tenantIds: input.tenantId ? [input.tenantId] : [], platform: true }, (tx) => audit(tx, { ...actor(ctx), tenantId: input.tenantId, action: "rbac.assign", targetType: "user", targetId: input.userId, detail: input }));
  if (role.key === STEWARD_ROLE && input.tenantId) await stewardRosterChanged(input.tenantId, input.userId, "added");
}

/** Granting or revoking a tenant role: user:manage on the tenant and the grant ceiling (see tenantRoleGrantDenial). */
async function assertTenantRoleGrant(ctx: AccessContext, role: { key: string; permissions: readonly string[] }, tenantId: string, opts: { revoking?: boolean } = {}) {
  assertCan(ctx, "user:manage", tenantId);
  const [tenant] = await withScope(dbScope(ctx, [tenantId]), (tx) => tx.select({ id: tenants.id, kind: tenants.kind }).from(tenants).where(eq(tenants.id, tenantId)));
  if (!tenant) throw new AccessDenied("tenant not in scope");
  const denial = tenantRoleGrantDenial(ctx, role, tenant, opts);
  if (denial) throw new AccessDenied(denial);
}

/** Stewards hear about every change to who can approve data rules, so a quiet addition cannot bypass the two-person rule. */
async function stewardRosterChanged(tenantId: string, userId: string, change: "added" | "removed") {
  const [person] = await db().select({ name: user.name }).from(user).where(eq(user.id, userId));
  await withScope(systemScope(tenantId), (tx) =>
    notifyStewards(tx, tenantId, { type: "user", id: userId }, "Data steward list changed", `${person?.name ?? "A user"} was ${change} as a data steward.`));
}

export async function revokeRole(ctx: AccessContext, assignmentId: string) {
  const [a] = await db().select().from(roleAssignments).where(eq(roleAssignments.id, assignmentId));
  if (!a) return;
  if (a.tenantId) {
    const [role] = await db().select().from(roles).where(eq(roles.key, a.roleKey));
    await assertTenantRoleGrant(ctx, { key: a.roleKey, permissions: role?.permissions ?? [] }, a.tenantId, { revoking: true });
  } else platformOnly(ctx, "user:manage");
  if (a.userId === ctx.principal.userId && !a.tenantId) throw new Error("you cannot revoke your own platform role");
  await db().delete(roleAssignments).where(eq(roleAssignments.id, assignmentId));
  await withScope({ tenantIds: a.tenantId ? [a.tenantId] : [], platform: true }, (tx) => audit(tx, { ...actor(ctx), tenantId: a.tenantId, action: "rbac.revoke", targetType: "user", targetId: a.userId, detail: { roleKey: a.roleKey } }));
  if (a.roleKey === STEWARD_ROLE && a.tenantId) await stewardRosterChanged(a.tenantId, a.userId, "removed");
}

export async function createCustomRole(ctx: AccessContext, input: { key: string; name: string; scope: "platform" | "tenant"; permissions: string[]; description?: string }) {
  platformOnly(ctx, "user:manage");
  const { PERMISSIONS } = await import("@/lib/auth/permissions");
  const bad = input.permissions.filter((p) => !(PERMISSIONS as readonly string[]).includes(p));
  if (bad.length) throw new Error(`unknown permissions: ${bad.join(", ")}`);
  await db().insert(roles).values({ ...input, key: `custom_${input.key}`, builtin: false });
  await withScope({ tenantIds: [], platform: true }, (tx) => audit(tx, { ...actor(ctx), tenantId: null, action: "rbac.role_create", targetType: "role", targetId: input.key, detail: input }));
}

export async function setUserDisabled(ctx: AccessContext, userId: string, disabled: boolean) {
  platformOnly(ctx, "user:manage");
  if (userId === ctx.principal.userId) throw new Error("you cannot disable yourself");
  await db().update(user).set({ disabled }).where(eq(user.id, userId));
  await withScope({ tenantIds: [], platform: true }, (tx) => audit(tx, { ...actor(ctx), tenantId: null, action: disabled ? "user.disable" : "user.enable", targetType: "user", targetId: userId }));
}

export async function listSsoProviders(ctx: AccessContext) {
  platformOnly(ctx, "settings:manage");
  return db().select({ id: ssoProvider.id, providerId: ssoProvider.providerId, issuer: ssoProvider.issuer, domain: ssoProvider.domain, tenantId: ssoProvider.tenantId, saml: sql<boolean>`${ssoProvider.samlConfig} is not null`, createdAt: ssoProvider.createdAt }).from(ssoProvider);
}

const NO_TENANT = "00000000-0000-0000-0000-000000000000";
const likeEscape = (v: string) => v.replace(/[\\%_]/g, (c) => `\\${c}`);
/** Calendar day in Sydney → the instant it starts. */
const sydneyDayStart = (day: string, plusDays = 0) => sql`((${day}::date + ${plusDays}::int)::timestamp at time zone 'Australia/Sydney')`;

/** Most rows one CSV export carries. */
export const AUDIT_EXPORT_CAP = 5000;

async function queryAudit(tx: Tx, tenantIds: string[], platform: boolean, f: AuditFilters, limit: number) {
  if (f.tenantId && !tenantIds.includes(f.tenantId)) throw new AccessDenied("tenant not in audit scope");
  const actorLike = f.actor ? `%${likeEscape(f.actor)}%` : undefined;
  const qLike = f.q ? `%${likeEscape(f.q)}%` : undefined;
  const ranged = !!(f.from || f.to);
  const rows = await tx
    .select({ entry: auditLog, actorName: sql<string | null>`coalesce(${user.name}, ${serviceIdentities.name})`, actorEmail: user.email, tenantName: tenants.name })
    .from(auditLog)
    .leftJoin(user, eq(user.id, auditLog.actorId))
    .leftJoin(serviceIdentities, and(eq(auditLog.actorKind, "service"), sql`${serviceIdentities.id}::text = ${auditLog.actorId}`))
    .leftJoin(tenants, eq(tenants.id, auditLog.tenantId))
    .where(and(
      f.tenantId ? eq(auditLog.tenantId, f.tenantId) : or(inArray(auditLog.tenantId, tenantIds.length ? tenantIds : [NO_TENANT]), platform ? isNull(auditLog.tenantId) : undefined),
      f.action ? sql`${auditLog.action} like ${`${likeEscape(f.action)}%`}` : undefined,
      ranged ? undefined : gte(auditLog.at, new Date(Date.now() - f.sinceDays * 86400_000)),
      f.from ? sql`${auditLog.at} >= ${sydneyDayStart(f.from)}` : undefined,
      f.to ? sql`${auditLog.at} < ${sydneyDayStart(f.to, 1)}` : undefined,
      f.actorKind ? eq(auditLog.actorKind, f.actorKind) : undefined,
      f.actor && actorLike ? or(eq(auditLog.actorId, f.actor), ilike(user.name, actorLike), ilike(user.email, actorLike), ilike(serviceIdentities.name, actorLike)) : undefined,
      f.targetType ? eq(auditLog.targetType, f.targetType) : undefined,
      f.targetId ? eq(auditLog.targetId, f.targetId) : undefined,
      qLike ? or(ilike(auditLog.action, qLike), ilike(auditLog.targetType, qLike), ilike(auditLog.targetId, qLike)) : undefined,
      f.before ? lt(auditLog.id, f.before) : undefined,
    ))
    .orderBy(desc(auditLog.id))
    .limit(limit + 1);
  const page = rows.slice(0, limit);
  const ids = [...new Set(page.flatMap((r) => auditNameIds(r.entry)))];
  const people = ids.length ? await tx.select({ id: user.id, name: user.name }).from(user).where(inArray(user.id, ids)) : [];
  return {
    rows: page,
    /** Cursor for the next (older) page, or null at the end. */
    nextBefore: rows.length > limit ? page.at(-1)!.entry.id : null,
    names: Object.fromEntries(people.map((p) => [p.id, p.name])) as Record<string, string>,
  };
}

/** Audit entries the caller may read, newest first, filtered in SQL. Pages by id: pass `nextBefore` back as `before`. */
export async function auditTrail(ctx: AccessContext, f: AuditFilters, limit = 300) {
  const platform = ctx.isPlatform && can(ctx, "audit:read");
  return scoped(ctx, "audit:read", (tx, tenantIds) => queryAudit(tx, tenantIds, platform, f, Math.min(Math.max(1, limit), 500)));
}

/**
 * Up to AUDIT_EXPORT_CAP entries for a CSV download, from the newest matching entry. The export is
 * itself audited, in the same transaction, against each customer whose entries it could contain.
 */
export async function exportAuditTrail(ctx: AccessContext, filters: AuditFilters, ip: string | null) {
  const platform = ctx.isPlatform && can(ctx, "audit:read");
  const f: AuditFilters = { ...filters, before: undefined };
  return scoped(ctx, "audit:read", async (tx, tenantIds) => {
    const res = await queryAudit(tx, tenantIds, platform, f, AUDIT_EXPORT_CAP);
    const capped = res.nextBefore !== null;
    const audited: (string | null)[] = f.tenantId ? [f.tenantId] : platform ? [null] : tenantIds;
    for (const tenantId of audited) {
      await audit(tx, { ...actor(ctx), tenantId, action: "audit.export", targetType: "audit_log", ip, detail: { filters: Object.fromEntries(Object.entries(f).filter(([, v]) => v !== undefined)), rows: res.rows.length, capped } });
    }
    return { rows: res.rows, names: res.names, capped };
  });
}

export async function verifyAudit(ctx: AccessContext) {
  platformOnly(ctx, "audit:read");
  return withScope({ tenantIds: [], platform: true }, (tx) => verifyAuditChain(tx));
}

const ENTRA_ISSUER = /^https:\/\/login\.microsoftonline\.com\/([0-9a-f-]{36})\/v2\.0\/?$/i;

/**
 * Entra ID endpoints are well known, so discovery is skipped for them. Discovery would
 * otherwise require login.microsoftonline.com in better-auth's trustedOrigins.
 */
function entraEndpoints(issuer: string) {
  const tid = ENTRA_ISSUER.exec(issuer)?.[1];
  if (!tid) return {};
  const base = `https://login.microsoftonline.com/${tid}`;
  return {
    skipDiscovery: true,
    authorizationEndpoint: `${base}/oauth2/v2.0/authorize`,
    tokenEndpoint: `${base}/oauth2/v2.0/token`,
    jwksEndpoint: `${base}/discovery/v2.0/keys`,
    userInfoEndpoint: "https://graph.microsoft.com/oidc/userinfo",
    tokenEndpointAuthentication: "client_secret_post" as const,
  };
}

export type SsoRegistration =
  | { protocol: "oidc"; providerId: string; domain: string; tenantId: string | null; issuer: string; clientId: string; clientSecret: string }
  | { protocol: "saml"; providerId: string; domain: string; tenantId: string | null; issuer: string; entryPoint: string; cert: string };

/**
 * Register an IdP through better-auth's SSO plugin (which also enforces providersLimit:
 * only platform_admin holders may register). `requestHeaders` carries the caller's session.
 */
export async function registerSsoProvider(ctx: AccessContext, input: SsoRegistration, requestHeaders: Headers) {
  platformOnly(ctx, "settings:manage");
  if (!/^[a-z0-9-]{2,40}$/.test(input.providerId)) throw new Error("provider id must be lowercase letters, digits, hyphens");
  if (input.tenantId) {
    const t = await listTenants(ctx);
    if (!t.some((x) => x.id === input.tenantId && x.kind === "customer")) throw new Error("unknown customer tenant");
  }
  // Loaded lazily so service tests do not need auth configuration.
  const [{ auth }, { APIError }] = await Promise.all([import("@/lib/auth/auth"), import("better-auth/api")]);
  const common = { providerId: input.providerId, issuer: input.issuer, domain: input.domain.toLowerCase(), tenantId: input.tenantId ?? undefined };
  const body =
    input.protocol === "oidc"
      ? { ...common, oidcConfig: { clientId: input.clientId, clientSecret: input.clientSecret, scopes: ["openid", "email", "profile"], pkce: true, ...entraEndpoints(input.issuer), ...googleEndpoints(input.issuer) } }
      : { ...common, samlConfig: { entryPoint: input.entryPoint, cert: input.cert, spMetadata: {} } };
  try {
    await auth.api.registerSSOProvider({ body, headers: requestHeaders });
  } catch (err) {
    // Surface the plugin's validation message (e.g. discovery failure) rather than a generic error.
    if (err instanceof APIError) throw new Error(err.message || "the identity provider was rejected");
    throw err;
  }
  await withScope({ tenantIds: input.tenantId ? [input.tenantId] : [], platform: true }, (tx) =>
    audit(tx, { ...actor(ctx), tenantId: input.tenantId, action: "sso.register", targetType: "sso_provider", targetId: input.providerId, detail: { protocol: input.protocol, issuer: input.issuer, domain: input.domain } }),
  );
}
