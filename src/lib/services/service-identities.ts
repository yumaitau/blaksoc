import { and, desc, eq, inArray, isNull, lt, or } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { withScope, type DbScope } from "@/db/scope";
import { serviceIdentities, serviceTokens, tenants } from "@/db/schema";
import { hashSecret, newSecret, SECRET_PREFIX, secretMatches, TOKEN_PREFIX, TOKEN_TTL_SECONDS } from "@/lib/api/tokens";
import { accessFromGrants, assertCan, can, dbScope, permissionsFor, type AccessContext } from "@/lib/auth/access";
import { PERMISSIONS, type Permission } from "@/lib/auth/permissions";
import { audit } from "@/lib/audit";
import { actor, AccessDenied, userRef } from "./common";

export type ServiceIdentityRow = typeof serviceIdentities.$inferSelect;

const isPermission = (p: string): p is Permission => (PERMISSIONS as readonly string[]).includes(p);
const platformManager = (ctx: AccessContext) => ctx.grants.some((g) => g.tenantId === null && g.permissions.has("user:manage"));

/**
 * Scopes `ctx` may put on an identity bound to `tenantId` (null = platform). Like role grants,
 * nobody hands out what they do not hold; a platform identity draws only on platform-wide grants.
 */
export function serviceScopeCeiling(ctx: AccessContext, tenantId: string | null): Set<Permission> {
  if (tenantId) return permissionsFor(ctx, tenantId);
  const out = new Set<Permission>();
  for (const g of ctx.grants) if (g.tenantId === null) g.permissions.forEach((p) => out.add(p));
  return out;
}

function assertManage(ctx: AccessContext, tenantId: string | null) {
  if (tenantId) assertCan(ctx, "user:manage", tenantId);
  else if (!platformManager(ctx)) throw new AccessDenied("platform user:manage required");
}

function assertCeiling(ctx: AccessContext, tenantId: string | null, scopes: readonly string[]) {
  const ceiling = serviceScopeCeiling(ctx, tenantId);
  const extra = scopes.filter((s) => !ceiling.has(s as Permission));
  if (extra.length) throw new AccessDenied(`cannot grant scopes you do not hold: ${extra.join(", ")}`);
}

const scopeOf = (ctx: AccessContext, tenantId: string | null): DbScope => (tenantId ? dbScope(ctx, [tenantId]) : { tenantIds: [], platform: true });

const listColumns = {
  id: serviceIdentities.id,
  tenantId: serviceIdentities.tenantId,
  tenantName: tenants.name,
  name: serviceIdentities.name,
  scopes: serviceIdentities.scopes,
  enabled: serviceIdentities.enabled,
  revokedAt: serviceIdentities.revokedAt,
  secretRotatedAt: serviceIdentities.secretRotatedAt,
  createdAt: serviceIdentities.createdAt,
  lastUsedAt: serviceIdentities.lastUsedAt,
};

/** Identities on tenants where the caller holds user:manage, plus platform identities for platform user managers. */
export async function listServiceIdentities(ctx: AccessContext) {
  const tenantIds = ctx.tenantIds.filter((t) => can(ctx, "user:manage", t));
  const platform = platformManager(ctx);
  if (!tenantIds.length && !platform) throw new AccessDenied("missing user:manage");
  return withScope(dbScope(ctx, tenantIds, platform), (tx) =>
    tx
      .select(listColumns)
      .from(serviceIdentities)
      .leftJoin(tenants, eq(tenants.id, serviceIdentities.tenantId))
      .where(or(inArray(serviceIdentities.tenantId, tenantIds.length ? tenantIds : ["00000000-0000-0000-0000-000000000000"]), platform ? isNull(serviceIdentities.tenantId) : undefined))
      .orderBy(desc(serviceIdentities.createdAt)),
  );
}

/** The client secret is returned once and never stored. */
export async function createServiceIdentity(ctx: AccessContext, input: { name: string; tenantId: string | null; scopes: string[] }) {
  const name = input.name.trim();
  if (name.length < 1 || name.length > 80) throw new Error("Name must be 1–80 characters.");
  const scopes = [...new Set(input.scopes)];
  const unknown = scopes.filter((s) => !isPermission(s));
  if (unknown.length) throw new Error(`Unknown scopes: ${unknown.join(", ")}.`);
  if (!scopes.length) throw new Error("Choose at least one scope.");
  assertManage(ctx, input.tenantId);
  assertCeiling(ctx, input.tenantId, scopes);
  const secret = newSecret(SECRET_PREFIX);
  const id = await withScope(scopeOf(ctx, input.tenantId), async (tx) => {
    const [row] = await tx
      .insert(serviceIdentities)
      .values({ tenantId: input.tenantId, name, scopes, secretHash: hashSecret(secret), createdBy: userRef(ctx) })
      .returning({ id: serviceIdentities.id });
    await audit(tx, { ...actor(ctx), tenantId: input.tenantId, action: "service_identity.create", targetType: "service_identity", targetId: row!.id, detail: { name, scopes } });
    return row!.id;
  });
  return { id, clientSecret: secret };
}

async function managed(ctx: AccessContext, id: string): Promise<ServiceIdentityRow> {
  // Read before a scope exists so the tenant is known; every write below runs under RLS.
  const [row] = await systemDb().select().from(serviceIdentities).where(eq(serviceIdentities.id, id));
  if (!row) throw new AccessDenied("service identity not found");
  assertManage(ctx, row.tenantId);
  return row;
}

async function change(ctx: AccessContext, row: ServiceIdentityRow, action: string, set: Partial<typeof serviceIdentities.$inferInsert>) {
  await withScope(scopeOf(ctx, row.tenantId), async (tx) => {
    const updated = await tx.update(serviceIdentities).set(set).where(eq(serviceIdentities.id, row.id)).returning({ id: serviceIdentities.id });
    if (!updated.length) throw new AccessDenied("service identity not found");
    // Outstanding tokens die with every change of credential or state.
    await tx.delete(serviceTokens).where(eq(serviceTokens.identityId, row.id));
    await audit(tx, { ...actor(ctx), tenantId: row.tenantId, action, targetType: "service_identity", targetId: row.id, detail: { name: row.name } });
  });
}

/** New secret; the old one and its tokens stop at once. Needs the ceiling: whoever rotates receives the identity's scopes. */
export async function rotateServiceSecret(ctx: AccessContext, id: string) {
  const row = await managed(ctx, id);
  if (row.revokedAt) throw new Error("This identity is revoked.");
  assertCeiling(ctx, row.tenantId, row.scopes);
  const secret = newSecret(SECRET_PREFIX);
  await change(ctx, row, "service_identity.rotate", { secretHash: hashSecret(secret), secretRotatedAt: new Date() });
  return { clientSecret: secret };
}

/** Disabling only removes access, so user:manage suffices; enabling restores it and needs the ceiling. */
export async function setServiceIdentityEnabled(ctx: AccessContext, id: string, enabled: boolean) {
  const row = await managed(ctx, id);
  if (row.revokedAt) throw new Error("This identity is revoked.");
  if (enabled) assertCeiling(ctx, row.tenantId, row.scopes);
  await change(ctx, row, enabled ? "service_identity.enable" : "service_identity.disable", { enabled });
}

/** Permanent. Any user manager on the tenant may do it, so a leaked credential can be killed quickly. */
export async function revokeServiceIdentity(ctx: AccessContext, id: string) {
  const row = await managed(ctx, id);
  if (row.revokedAt) return;
  await change(ctx, row, "service_identity.revoke", { enabled: false, revokedAt: new Date() });
}

// Compared against when the client id is unknown, so a miss costs the same as a wrong secret.
const NO_SECRET = hashSecret("no such client");

/** OAuth client_credentials grant. Null for any failure: the caller answers invalid_client. */
export async function issueServiceToken(input: { clientId: string; clientSecret: string; ip?: string | null; now?: Date }) {
  const now = input.now ?? new Date();
  const [row] = await systemDb().select().from(serviceIdentities).where(eq(serviceIdentities.id, input.clientId));
  const secretOk = secretMatches(input.clientSecret, row?.secretHash ?? NO_SECRET);
  if (!row) return null;
  if (!secretOk || !row.enabled || row.revokedAt) {
    await audit(systemDb(), { actorId: row.id, actorKind: "service", tenantId: row.tenantId, action: "api.token_denied", targetType: "service_identity", targetId: row.id, ip: input.ip, detail: { reason: !secretOk ? "secret" : row.revokedAt ? "revoked" : "disabled" } });
    return null;
  }
  const accessToken = newSecret(TOKEN_PREFIX);
  const expiresAt = new Date(now.getTime() + TOKEN_TTL_SECONDS * 1000);
  const scopes = row.scopes.filter(isPermission);
  await systemDb().transaction(async (tx) => {
    await tx.delete(serviceTokens).where(and(eq(serviceTokens.identityId, row.id), lt(serviceTokens.expiresAt, now)));
    await tx.insert(serviceTokens).values({ tokenHash: hashSecret(accessToken), identityId: row.id, tenantId: row.tenantId, expiresAt });
    await audit(tx, { actorId: row.id, actorKind: "service", tenantId: row.tenantId, action: "api.token", targetType: "service_identity", targetId: row.id, ip: input.ip, detail: { expiresAt: expiresAt.toISOString() } });
  });
  return { accessToken, expiresIn: TOKEN_TTL_SECONDS, scopes };
}

export type ServiceCaller = { ctx: AccessContext; identity: { id: string; name: string; tenantId: string | null } };

/**
 * AccessContext for a bearer token: one grant carrying the identity's scopes on its tenant (or
 * platform-wide), expanded exactly as a user's role would be, so services, RLS and audit apply unchanged.
 * Identity state is read on every call, so disabling or revoking takes effect immediately.
 */
export async function authenticateServiceToken(token: string, now = new Date()): Promise<ServiceCaller | null> {
  // Lookup by SHA-256 of a 256-bit token: timing reveals nothing usable about other tokens.
  const [row] = await systemDb()
    .select({ identity: serviceIdentities, expiresAt: serviceTokens.expiresAt })
    .from(serviceTokens)
    .innerJoin(serviceIdentities, eq(serviceIdentities.id, serviceTokens.identityId))
    .where(eq(serviceTokens.tokenHash, hashSecret(token)));
  if (!row || row.expiresAt <= now || !row.identity.enabled || row.identity.revokedAt) return null;
  const { identity } = row;
  const ctx = await accessFromGrants(
    { userId: identity.id, name: identity.name, email: "", isBreakGlass: false, kind: "service" },
    [{ roleKey: "service_identity", tenantId: identity.tenantId, permissions: new Set(identity.scopes.filter(isPermission)) }],
  );
  if (!identity.lastUsedAt || now.getTime() - identity.lastUsedAt.getTime() > 60_000) {
    await systemDb().update(serviceIdentities).set({ lastUsedAt: now }).where(eq(serviceIdentities.id, identity.id));
  }
  return { ctx, identity: { id: identity.id, name: identity.name, tenantId: identity.tenantId } };
}
