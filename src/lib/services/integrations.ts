import { and, desc, eq, inArray, isNull, or, sql } from "drizzle-orm";
import { auditLog, integrations, integrationTenantLinks, tenants } from "@/db/schema";
import { withScope } from "@/db/scope";
import { can, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { instantiate, secretAad } from "@/lib/connectors/instances";
import { connectorDef, CONNECTORS } from "@/lib/connectors/registry";
import { stampSyslogTenant } from "@/lib/services/syslog";
import { encryptSecret } from "@/lib/crypto";
import { actor, AccessDenied, scoped } from "./common";

/** Columns safe for the browser. secretCiphertext is never selected here. */
const PUBLIC_COLUMNS = {
  id: integrations.id, tenantId: integrations.tenantId, category: integrations.category, provider: integrations.provider, name: integrations.name,
  config: integrations.config, enabled: integrations.enabled, status: integrations.status, permissions: integrations.permissions,
  lastSuccessAt: integrations.lastSuccessAt, lastError: integrations.lastError, lastErrorAt: integrations.lastErrorAt, health: integrations.health,
  createdAt: integrations.createdAt,
  hasSecret: sql<boolean>`${integrations.secretCiphertext} is not null`,
};

export async function listIntegrations(ctx: AccessContext) {
  return scoped(ctx, "integration:read", async (tx, ids) => {
    const rows = await tx
      .select({ ...PUBLIC_COLUMNS, tenantName: tenants.name })
      .from(integrations)
      .leftJoin(tenants, eq(tenants.id, integrations.tenantId))
      .where(or(inArray(integrations.tenantId, ids), ctx.isPlatform ? isNull(integrations.tenantId) : undefined))
      .orderBy(integrations.category, integrations.name);
    const links = rows.length ? await tx.select({ integrationId: integrationTenantLinks.integrationId, tenantId: integrationTenantLinks.tenantId, selector: integrationTenantLinks.selector, tenantName: tenants.name }).from(integrationTenantLinks).innerJoin(tenants, eq(tenants.id, integrationTenantLinks.tenantId)).where(inArray(integrationTenantLinks.integrationId, rows.map((r) => r.id))) : [];
    return rows.map((r) => ({ ...r, links: links.filter((l) => l.integrationId === r.id) }));
  });
}

export async function integrationAudit(ctx: AccessContext, id: string) {
  return scoped(ctx, "integration:read", (tx) => tx.select().from(auditLog).where(and(eq(auditLog.targetType, "integration"), eq(auditLog.targetId, id))).orderBy(desc(auditLog.at)).limit(50));
}

export function catalogue() {
  return CONNECTORS.map(({ create: _c, config: _cfg, secrets: _s, ...rest }) => rest);
}

function assertManage(ctx: AccessContext, tenantId: string | null) {
  if (tenantId ? !can(ctx, "integration:manage", tenantId) : !(ctx.isPlatform && can(ctx, "integration:manage"))) throw new AccessDenied("missing integration:manage");
}

export async function createIntegration(ctx: AccessContext, input: { tenantId: string | null; provider: string; name: string; config: unknown; secrets: unknown }) {
  assertManage(ctx, input.tenantId);
  const def = connectorDef(input.provider);
  if (!def || def.status !== "available") throw new Error(`connector ${input.provider} is not available`);
  const config = stampSyslogTenant(def.provider, def.config.parse(input.config) as Record<string, unknown>, input.tenantId);
  const secrets = def.secrets.parse(input.secrets ?? {});
  return withScope({ tenantIds: input.tenantId ? [input.tenantId] : [], platform: !input.tenantId }, async (tx) => {
    const [row] = await tx.insert(integrations).values({ tenantId: input.tenantId, category: def.category, provider: def.provider, name: input.name, config, permissions: def.remotePermissions }).returning({ id: integrations.id });
    if (Object.keys(secrets).length) {
      await tx.update(integrations).set({ secretCiphertext: encryptSecret(JSON.stringify(secrets), secretAad(row!.id)) }).where(eq(integrations.id, row!.id));
    }
    await audit(tx, { ...actor(ctx), tenantId: input.tenantId, action: "integration.create", targetType: "integration", targetId: row!.id, detail: { provider: def.provider, name: input.name, secretKeys: Object.keys(secrets) } });
    return row!.id;
  });
}

/** Secrets are write-only: omitted keys keep their stored values. */
export async function updateIntegration(ctx: AccessContext, id: string, input: { name?: string; config?: unknown; secrets?: Record<string, string>; enabled?: boolean }) {
  return scoped(ctx, "integration:manage", async (tx) => {
    const [cur] = await tx.select().from(integrations).where(eq(integrations.id, id));
    if (!cur) throw new AccessDenied("integration not found");
    assertManage(ctx, cur.tenantId);
    const def = connectorDef(cur.provider)!;
    const patch: Partial<typeof integrations.$inferInsert> = {};
    if (input.name) patch.name = input.name;
    if (input.enabled !== undefined) patch.enabled = input.enabled;
    if (input.config !== undefined) patch.config = stampSyslogTenant(cur.provider, def.config.parse(input.config) as Record<string, unknown>, cur.tenantId);
    if (input.secrets && Object.values(input.secrets).some(Boolean)) {
      const existing = cur.secretCiphertext ? (JSON.parse((await import("@/lib/crypto")).decryptSecret(cur.secretCiphertext, secretAad(id))) as Record<string, string>) : {};
      const merged = def.secrets.parse({ ...existing, ...Object.fromEntries(Object.entries(input.secrets).filter(([, v]) => v)) });
      patch.secretCiphertext = encryptSecret(JSON.stringify(merged), secretAad(id));
    }
    await tx.update(integrations).set(patch).where(eq(integrations.id, id));
    await audit(tx, { ...actor(ctx), tenantId: cur.tenantId, action: "integration.update", targetType: "integration", targetId: id, detail: { fields: Object.keys(patch).map((k) => (k === "secretCiphertext" ? "secrets" : k)) } });
  });
}

export async function linkTenant(ctx: AccessContext, integrationId: string, tenantId: string, selector: { agentGroups?: string[] }) {
  if (!ctx.isPlatform || !can(ctx, "integration:manage", tenantId)) throw new AccessDenied();
  await withScope({ tenantIds: [tenantId], platform: true }, async (tx) => {
    await tx.insert(integrationTenantLinks).values({ integrationId, tenantId, selector }).onConflictDoUpdate({ target: [integrationTenantLinks.integrationId, integrationTenantLinks.tenantId], set: { selector } });
    await audit(tx, { ...actor(ctx), tenantId, action: "integration.link_tenant", targetType: "integration", targetId: integrationId, detail: { selector } });
  });
}

/** Live health check; records status/last error on the row. */
export async function testIntegration(ctx: AccessContext, id: string) {
  return scoped(ctx, "integration:manage", async (tx) => {
    const [row] = await tx.select().from(integrations).where(eq(integrations.id, id));
    if (!row) throw new AccessDenied("integration not found");
    let health: { ok: boolean; latencyMs: number; detail?: Record<string, unknown>; error?: string };
    try {
      const inst = instantiate(row);
      health = inst.kind === "notify" ? { ok: true, latencyMs: 0, detail: { note: "send a test notification to verify" } } : await inst.provider.health();
    } catch (err) {
      health = { ok: false, latencyMs: 0, error: (err as Error).message };
    }
    const now = new Date();
    await tx
      .update(integrations)
      .set({ status: health.ok ? "healthy" : "error", health: health as never, ...(health.ok ? { lastSuccessAt: now } : { lastError: health.error ?? "unknown error", lastErrorAt: now }) })
      .where(eq(integrations.id, id));
    await audit(tx, { ...actor(ctx), tenantId: row.tenantId, action: "integration.test", targetType: "integration", targetId: id, detail: { ok: health.ok } });
    return health;
  });
}
