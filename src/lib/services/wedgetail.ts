import { and, eq, sql } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { alerts, integrations } from "@/db/schema";
import { withScope } from "@/db/scope";
import { audit } from "@/lib/audit";
import { systemScope } from "@/lib/auth/access";
import { intelProviderFor, secretAad, type IntegrationRow } from "@/lib/connectors/instances";
import { decryptSecret } from "@/lib/crypto";
import { ingestAlerts, ingestLag } from "@/lib/obs/metrics";
import { ingestAlert, IngestIntegrationConflict, IngestIntegrationUnavailable } from "@/lib/pipeline/ingest";
import { normaliseWedgetail, unhandledWedgetailEvent, verifyWedgetail, wedgetailEvent, WEDGETAIL_BODY_LIMIT, WEDGETAIL_STATUSES, type WedgetailUpdate } from "@/lib/providers/wedgetail";
import { evaluateTriggers } from "@/lib/soar/engine";

export class WedgetailError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}
export type WedgetailIntegration = IntegrationRow & { tenantId: string };
export type WedgetailOutcome = "created" | "duplicate" | "unrouted" | "rejected" | "ignored";

/** System connection is only for credential resolution before a tenant is known. */
export async function wedgetailIntegration(id: string): Promise<WedgetailIntegration | null> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
  const [row] = await systemDb().select().from(integrations).where(and(eq(integrations.id, id), eq(integrations.provider, "wedgetail"), eq(integrations.enabled, true)));
  return row?.tenantId && row.secretCiphertext ? row as WedgetailIntegration : null;
}

/** Atomic jsonb increment: simultaneous deliveries do not lose counts. No payload or credential in health. */
export async function recordWedgetailOutcome(row: WedgetailIntegration | null, outcome: WedgetailOutcome) {
  ingestAlerts().inc({ provider: "wedgetail", integration: row?.id ?? "unknown", outcome });
  if (!row) return;
  const now = new Date();
  await withScope(systemScope(row.tenantId), (tx) => tx.update(integrations).set({
    health: sql`jsonb_build_object('ok', true, 'latencyMs', 0, 'detail', ('{"created":0,"duplicate":0,"unrouted":0,"rejected":0,"ignored":0}'::jsonb || coalesce(${integrations.health}->'detail', '{}'::jsonb)) || jsonb_build_object(${outcome}::text, coalesce((${integrations.health}->'detail'->>${outcome})::bigint, 0) + 1) ${outcome !== "rejected" ? sql`|| jsonb_build_object('lastReceivedAt', ${now.toISOString()}::text)` : sql``})`,
    ...(outcome !== "rejected" ? { status: "healthy", lastSuccessAt: now } : {}),
  }).where(and(eq(integrations.id, row.id), eq(integrations.tenantId, row.tenantId))));
}

/** Status updates are tenant AND install scoped, audited in the same transaction, and never published to notify. */
export async function applyWedgetailStatus(row: WedgetailIntegration, event: WedgetailUpdate) {
  return withScope(systemScope(row.tenantId), async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`${row.tenantId}|wedgetail|${event.alert.id}`}, 0))`);
    const [integration] = await tx.select({ enabled: integrations.enabled }).from(integrations).where(and(eq(integrations.id, row.id), eq(integrations.tenantId, row.tenantId), eq(integrations.provider, "wedgetail"))).for("share");
    if (!integration?.enabled) throw new WedgetailError(404, "not_found");
    const [alert] = await tx.select().from(alerts).where(and(eq(alerts.tenantId, row.tenantId), eq(alerts.integrationId, row.id), eq(alerts.source, "wedgetail"), eq(alerts.externalId, event.alert.id))).for("update");
    if (!alert) return null;
    const raw = (alert.raw ?? {}) as Record<string, unknown>;
    const sync = raw.wedgetailSync as { updatedAt?: string } | undefined;
    // Old/repeated events cannot reopen a finding closed by a newer event.
    if (sync?.updatedAt && Date.parse(event.alert.updatedAt) <= Date.parse(sync.updatedAt)) return { alertId: alert.id, changed: false };
    const status = WEDGETAIL_STATUSES[event.alert.status];
    await tx.update(alerts).set({ status, updatedAt: new Date(), raw: { ...raw, wedgetailSync: { updatedAt: event.alert.updatedAt } } }).where(and(eq(alerts.id, alert.id), eq(alerts.tenantId, row.tenantId)));
    if (status !== alert.status) await audit(tx, {
      actorId: `wedgetail:${row.id}`, actorKind: "system", tenantId: row.tenantId, action: "alert.update", targetType: "alert", targetId: alert.id,
      detail: { from: alert.status, status, integrationId: row.id, origin: "wedgetail", occurredAt: event.alert.updatedAt },
    });
    return { alertId: alert.id, changed: status !== alert.status };
  });
}

export async function acceptWedgetail(row: WedgetailIntegration, body: Uint8Array, headers: Headers) {
  if (body.byteLength > WEDGETAIL_BODY_LIMIT) throw new WedgetailError(413, "size");
  let secret: string;
  try {
    const stored = JSON.parse(decryptSecret(row.secretCiphertext!, secretAad(row.id))) as { signingSecret?: unknown };
    secret = typeof stored.signingSecret === "string" ? stored.signingSecret : "";
  } catch { throw new WedgetailError(401, "unauthorised"); }
  if (!verifyWedgetail(body, headers, secret)) throw new WedgetailError(401, "unauthorised");
  let payload: unknown;
  try { payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)); }
  catch { throw new WedgetailError(400, "invalid_event"); }
  if (unhandledWedgetailEvent.safeParse(payload).success) {
    await recordWedgetailOutcome(row, "ignored");
    return { outcome: "ignored" };
  }
  const parsed = wedgetailEvent.safeParse(payload);
  if (!parsed.success) throw new WedgetailError(400, "invalid_event");
  const event = parsed.data;
  if ("type" in event && event.type === "wedgetail.alert.updated") {
    const result = await applyWedgetailStatus(row, event);
    await recordWedgetailOutcome(row, result ? "duplicate" : "unrouted");
    if (!result) throw new WedgetailError(409, "unrouted");
    return { outcome: "duplicate", ...result };
  }
  const alert = normaliseWedgetail(event);
  const intel = await withScope(systemScope(row.tenantId), (tx) => intelProviderFor(tx, row.tenantId));
  let result;
  try {
    result = await ingestAlert({ tenantId: row.tenantId, integrationId: row.id, source: "wedgetail", alert, intel: intel?.provider ?? null, updateExisting: true });
  } catch (err) {
    if (err instanceof IngestIntegrationUnavailable) throw new WedgetailError(404, "not_found");
    if (err instanceof IngestIntegrationConflict) {
      await recordWedgetailOutcome(row, "unrouted");
      throw new WedgetailError(409, "unrouted");
    }
    throw err;
  }
  const outcome = result.created ? "created" : "duplicate";
  await recordWedgetailOutcome(row, outcome);
  if (result.created) {
    ingestLag().observe({ integration: row.id, provider: "wedgetail" }, Math.max(0, Date.now() - alert.occurredAt.getTime()) / 1000);
    await evaluateTriggers(row.tenantId, "alert.created", { alertId: result.alertId });
  }
  return { outcome, alertId: result.alertId };
}
