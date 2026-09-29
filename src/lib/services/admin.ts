import { and, desc, eq, gte, inArray, isNull, or, sql } from "drizzle-orm";
import { db } from "@/db/client";
import { auditLog, DEFAULT_TENANT_SETTINGS, roleAssignments, roles, sites, ssoProvider, tenants, user, type TenantSettings } from "@/db/schema";
import { withScope } from "@/db/scope";
import { assertCan, can, type AccessContext } from "@/lib/auth/access";
import { audit, verifyAuditChain } from "@/lib/audit";
import { actor, AccessDenied } from "./common";

const platformOnly = (ctx: AccessContext, perm: "tenant:manage" | "user:manage" | "settings:manage" | "audit:read") => {
  if (!ctx.isPlatform || !can(ctx, perm)) throw new AccessDenied(`platform ${perm} required`);
};

export async function listTenants(ctx: AccessContext) {
  return withScope({ tenantIds: ctx.tenantIds, platform: ctx.isPlatform }, (tx) => tx.select().from(tenants).where(inArray(tenants.id, ctx.tenantIds.length ? ctx.tenantIds : ["00000000-0000-0000-0000-000000000000"])).orderBy(tenants.kind, tenants.name));
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
  return withScope({ tenantIds: [tenantId], platform: true }, async (tx) => {
    const [t] = await tx.select().from(tenants).where(eq(tenants.id, tenantId));
    if (!t) throw new AccessDenied();
    const settings = { ...t.settings, ...patch, sharing: { ...t.settings.sharing, ...patch.sharing }, ai: { ...t.settings.ai, ...patch.ai }, slaMinutes: { ...t.settings.slaMinutes, ...patch.slaMinutes } };
    await tx.update(tenants).set({ settings }).where(eq(tenants.id, tenantId));
    await audit(tx, { ...actor(ctx), tenantId, action: "tenant.settings", targetType: "tenant", targetId: tenantId, detail: { before: t.settings, after: settings } });
    return settings;
  });
}

export async function createSite(ctx: AccessContext, tenantId: string, name: string, location?: string, link: "standard" | "low" = "standard") {
  assertCan(ctx, "asset:write", tenantId);
  return withScope({ tenantIds: [tenantId], platform: false }, (tx) => tx.insert(sites).values({ tenantId, name, location, bandwidthProfile: link }).returning());
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
    assertCan(ctx, "user:manage", input.tenantId);
  }
  await db().insert(roleAssignments).values({ userId: input.userId, roleKey: input.roleKey, tenantId: input.tenantId, createdBy: ctx.principal.userId }).onConflictDoNothing();
  await withScope({ tenantIds: input.tenantId ? [input.tenantId] : [], platform: true }, (tx) => audit(tx, { ...actor(ctx), tenantId: input.tenantId, action: "rbac.assign", targetType: "user", targetId: input.userId, detail: input }));
}

export async function revokeRole(ctx: AccessContext, assignmentId: string) {
  const [a] = await db().select().from(roleAssignments).where(eq(roleAssignments.id, assignmentId));
  if (!a) return;
  if (a.tenantId) assertCan(ctx, "user:manage", a.tenantId);
  else platformOnly(ctx, "user:manage");
  if (a.userId === ctx.principal.userId && !a.tenantId) throw new Error("you cannot revoke your own platform role");
  await db().delete(roleAssignments).where(eq(roleAssignments.id, assignmentId));
  await withScope({ tenantIds: a.tenantId ? [a.tenantId] : [], platform: true }, (tx) => audit(tx, { ...actor(ctx), tenantId: a.tenantId, action: "rbac.revoke", targetType: "user", targetId: a.userId, detail: { roleKey: a.roleKey } }));
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

export async function auditTrail(ctx: AccessContext, f: { tenantId?: string; action?: string; sinceDays?: number; limit?: number } = {}) {
  const tenantIds = ctx.tenantIds.filter((t) => can(ctx, "audit:read", t));
  if (!tenantIds.length && !(ctx.isPlatform && can(ctx, "audit:read"))) throw new AccessDenied();
  return withScope({ tenantIds, platform: ctx.isPlatform && can(ctx, "audit:read") }, (tx) =>
    tx
      .select({ entry: auditLog, actorName: user.name, tenantName: tenants.name })
      .from(auditLog)
      .leftJoin(user, eq(user.id, auditLog.actorId))
      .leftJoin(tenants, eq(tenants.id, auditLog.tenantId))
      .where(and(
        f.tenantId ? eq(auditLog.tenantId, f.tenantId) : or(inArray(auditLog.tenantId, tenantIds.length ? tenantIds : ["00000000-0000-0000-0000-000000000000"]), ctx.isPlatform ? isNull(auditLog.tenantId) : undefined),
        f.action ? sql`${auditLog.action} like ${`${f.action}%`}` : undefined,
        gte(auditLog.at, new Date(Date.now() - (f.sinceDays ?? 30) * 86400_000)),
      ))
      .orderBy(desc(auditLog.id))
      .limit(f.limit ?? 200),
  );
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
      ? { ...common, oidcConfig: { clientId: input.clientId, clientSecret: input.clientSecret, scopes: ["openid", "email", "profile"], pkce: true, ...entraEndpoints(input.issuer) } }
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
