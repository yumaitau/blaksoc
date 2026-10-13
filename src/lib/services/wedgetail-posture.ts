import { and, eq, inArray } from "drizzle-orm";
import { systemDb, type DbOrTx } from "@/db/client";
import { withScope } from "@/db/scope";
import { dataGovernance, integrations, MOST_PROTECTIVE, wedgetailPosture } from "@/db/schema";
import { assertCan, systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { secretAad, type IntegrationRow } from "@/lib/connectors/instances";
import { connectorDef } from "@/lib/connectors/registry";
import { decryptSecret } from "@/lib/crypto";
import { checkGovernedRegion } from "@/lib/governance/policy";
import { logger } from "@/lib/obs/log";
import { scoped } from "./common";
import { fetchPosture, mcpClient, WedgetailApiError, type McpCall } from "@/lib/wedgetail/posture";

/** Posture changes slowly; an install allows 60 MCP calls a minute and each pull makes three. */
export const POSTURE_EVERY_MS = 60 * 60_000;

export type PostureConnect = (consoleUrl: string, token: string) => McpCall;

type Counts = { pulled: number; failed: number; skipped: number };

function backoff(attempts: number, now: Date): Date {
  return new Date(now.getTime() + Math.min(24 * 60, 60 * 2 ** Math.min(attempts - 1, 5)) * 60_000);
}

function credentials(row: IntegrationRow): { consoleUrl: string; token: string } | null {
  const def = connectorDef("wedgetail")!;
  const config = def.config.safeParse(row.config);
  const consoleUrl = config.success ? (config.data as { consoleUrl?: string }).consoleUrl : undefined;
  if (!consoleUrl || !row.secretCiphertext) return null;
  const secrets = JSON.parse(decryptSecret(row.secretCiphertext, secretAad(row.id))) as { mcpToken?: string };
  return secrets.mcpToken ? { consoleUrl, token: secrets.mcpToken } : null;
}

/**
 * Pull ISM status, the Essential Eight summary and ATT&CK coverage from every enabled Wedgetail install that has a console URL and
 * MCP token, when due. A failure keeps the last good snapshot and backs off; a refused token waits a day.
 */
export async function syncWedgetailPosture(opts: { now?: Date; connect?: PostureConnect; force?: string } = {}): Promise<Counts> {
  const now = opts.now ?? new Date();
  const connect = opts.connect ?? ((url, token) => mcpClient(url, token));
  const counts: Counts = { pulled: 0, failed: 0, skipped: 0 };
  const rows = await systemDb().select().from(integrations).where(and(eq(integrations.provider, "wedgetail"), eq(integrations.enabled, true), ...(opts.force ? [eq(integrations.id, opts.force)] : [])));
  for (const row of rows) {
    const tenantId = row.tenantId;
    if (!tenantId) continue;
    let creds: ReturnType<typeof credentials>;
    try {
      creds = credentials(row);
    } catch (err) {
      logger.warn("wedgetail posture credentials unreadable", { integrationId: row.id, err });
      creds = null;
    }
    if (!creds) { counts.skipped++; continue; }
    const [gov] = await systemDb().select({ profile: dataGovernance.profile }).from(dataGovernance).where(eq(dataGovernance.tenantId, tenantId));
    if (!checkGovernedRegion(gov?.profile ?? MOST_PROTECTIVE, row.config.region).allowed) { counts.skipped++; continue; }

    const [state] = await withScope(systemScope(tenantId), (tx) => tx.select().from(wedgetailPosture).where(eq(wedgetailPosture.integrationId, row.id)));
    if (!opts.force && state && state.nextAttemptAt > now) { counts.skipped++; continue; }
    try {
      const posture = await fetchPosture(connect(creds.consoleUrl, creds.token));
      const values = { ism: posture.ism, mitre: posture.mitre, e8: posture.e8, fetchedAt: now, attemptedAt: now, attempts: 0, nextAttemptAt: new Date(now.getTime() + POSTURE_EVERY_MS), lastError: null };
      await withScope(systemScope(tenantId), (tx) =>
        tx.insert(wedgetailPosture).values({ integrationId: row.id, tenantId, ...values }).onConflictDoUpdate({ target: wedgetailPosture.integrationId, set: values }));
      counts.pulled++;
    } catch (err) {
      counts.failed++;
      const attempts = (state?.attempts ?? 0) + 1;
      const lastError = (err instanceof WedgetailApiError ? err.message : err instanceof Error && err.name === "ZodError" ? "Wedgetail returned data in an unexpected shape." : "Could not reach the Wedgetail install.").slice(0, 300);
      const nextAttemptAt = err instanceof WedgetailApiError && err.permanent ? new Date(now.getTime() + 24 * 3600_000) : backoff(attempts, now);
      if (!(err instanceof WedgetailApiError)) logger.warn("wedgetail posture pull failed", { integrationId: row.id, err });
      await withScope(systemScope(tenantId), (tx) =>
        tx.insert(wedgetailPosture).values({ integrationId: row.id, tenantId, attemptedAt: now, attempts, nextAttemptAt, lastError })
          .onConflictDoUpdate({ target: wedgetailPosture.integrationId, set: { attemptedAt: now, attempts, nextAttemptAt, lastError } }));
    }
  }
  return counts;
}

/** Snapshots for the given tenants, inside the caller's scope. */
export async function postureFor(tx: DbOrTx, tenantIds: readonly string[]) {
  if (!tenantIds.length) return [];
  return tx.select().from(wedgetailPosture).where(inArray(wedgetailPosture.tenantId, [...tenantIds]));
}

/** "Pull now" from the integration page: same pull, run immediately for one install the caller manages. */
export async function refreshWedgetailPosture(ctx: AccessContext, integrationId: string) {
  const [row] = await systemDb().select({ tenantId: integrations.tenantId, provider: integrations.provider }).from(integrations).where(eq(integrations.id, integrationId));
  if (!row?.tenantId || row.provider !== "wedgetail") throw new Error("Not a Wedgetail integration.");
  assertCan(ctx, "integration:manage", row.tenantId);
  const counts = await syncWedgetailPosture({ force: integrationId });
  const [state] = await withScope(systemScope(row.tenantId), async (tx) => {
    const found = await tx.select().from(wedgetailPosture).where(eq(wedgetailPosture.integrationId, integrationId));
    await audit(tx, { actorId: ctx.principal.userId, actorKind: ctx.principal.kind === "service" ? "service" : "user", tenantId: row.tenantId, action: "integration.wedgetail_posture", targetType: "integration", targetId: integrationId, detail: { ok: counts.pulled > 0 } });
    return found;
  });
  if (!counts.pulled && !counts.failed) return { ok: false, error: "Set a console URL and MCP token first." };
  return { ok: counts.pulled > 0, error: state?.lastError ?? undefined };
}

export async function readWedgetailPosture(ctx: AccessContext, integrationId: string) {
  return scoped(ctx, "integration:read", async (tx) => {
    const [row] = await tx.select().from(wedgetailPosture).where(eq(wedgetailPosture.integrationId, integrationId));
    return row ?? null;
  });
}
