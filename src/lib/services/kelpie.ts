import { and, asc, eq, inArray, isNull, lte, min, ne } from "drizzle-orm";
import { systemDb, type DbOrTx } from "@/db/client";
import { withScope } from "@/db/scope";
import { alerts, dataGovernance, incidentAlerts, incidentLinks, incidents, incidentTasks, incidentTimeline, integrations, kelpieCases, MOST_PROTECTIVE, tenants } from "@/db/schema";
import { systemScope } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { instantiate, type IntegrationRow } from "@/lib/connectors/instances";
import { env } from "@/lib/env";
import { publish } from "@/lib/events";
import { checkGovernedRegion } from "@/lib/governance/policy";
import { KelpieError, type KelpieClient } from "@/lib/kelpie/client";
import { caseFromIncident, incidentStatusFor, kelpieObservable } from "@/lib/kelpie/map";
import { detectionContext, mergeDetectionContext } from "@/lib/incidents/explanation";
import { incidentDetections } from "./incident-context";

/** Raised when an analyst edits a case that Kelpie owns. The message is safe to show. */
export class KelpieManaged extends Error {
  constructor(caseNumber: string | null) {
    super(`This case is managed in Kelpie${caseNumber ? ` (${caseNumber})` : ""}. Make the change there.`);
    this.name = "KelpieManaged";
  }
}

export type KelpieConnect = (row: IntegrationRow) => KelpieClient;

const defaultConnect: KelpieConnect = (row) => {
  const inst = instantiate(row);
  if (inst.kind !== "cases") throw new Error(`${row.provider} is not a case manager`);
  return inst.provider;
};

/** The tenant's own enabled Kelpie integration. Kelpie never serves a tenant through a platform-owned row. */
export async function kelpieIntegration(tx: DbOrTx, tenantId: string): Promise<IntegrationRow | null> {
  const [row] = await tx
    .select()
    .from(integrations)
    .where(and(eq(integrations.tenantId, tenantId), eq(integrations.provider, "kelpie"), eq(integrations.enabled, true)))
    .limit(1);
  return row ?? null;
}

/** Throws when Kelpie owns this tenant's case work. Called by blakSOC's own case edits. */
export async function assertNotKelpieManaged(tx: DbOrTx, tenantId: string, incidentId: string) {
  if (!(await kelpieIntegration(tx, tenantId))) return;
  const [link] = await tx.select({ caseNumber: kelpieCases.caseNumber }).from(kelpieCases).where(eq(kelpieCases.incidentId, incidentId));
  throw new KelpieManaged(link?.caseNumber ?? null);
}

export async function kelpieLink(tx: DbOrTx, incidentId: string) {
  const [row] = await tx.select().from(kelpieCases).where(eq(kelpieCases.incidentId, incidentId));
  return row ?? null;
}

function backoff(attempts: number, now: Date): Date {
  return new Date(now.getTime() + Math.min(60, 2 ** Math.min(attempts, 6)) * 60_000);
}

function message(err: unknown): string {
  return (err instanceof Error ? err.message : "Kelpie request failed").slice(0, 300);
}

type Counts = { queued: number; pushed: number; failed: number; synced: number; forwarded: number };

async function failed(tenantId: string, incidentId: string, attempts: number, err: unknown, now: Date) {
  await withScope(systemScope(tenantId), (tx) =>
    tx.update(kelpieCases).set({ attempts: attempts + 1, lastError: message(err), nextAttemptAt: backoff(attempts + 1, now) }).where(eq(kelpieCases.incidentId, incidentId)));
}

async function pushCase(client: KelpieClient, row: typeof kelpieCases.$inferSelect, slug: string, now: Date): Promise<boolean> {
  const tenantId = row.tenantId;
  const body = await withScope(systemScope(tenantId), async (tx) => {
    const [inc] = await tx.select().from(incidents).where(eq(incidents.id, row.incidentId));
    if (!inc) return null;
    const links = await tx.select({ kind: incidentLinks.kind, label: incidentLinks.label }).from(incidentLinks).where(eq(incidentLinks.incidentId, inc.id));
    const [first] = await tx
      .select({ at: min(alerts.occurredAt) })
      .from(incidentAlerts)
      .innerJoin(alerts, eq(alerts.id, incidentAlerts.alertId))
      .where(eq(incidentAlerts.incidentId, inc.id));
    const detections = await incidentDetections(tx, inc.id);
    return caseFromIncident({ ...inc, firstSeen: first?.at ?? null, tenantSlug: slug, links, alerts: detections }, env().APP_URL);
  });
  if (!body) return false;
  try {
    const created = await client.createCase(body);
    await withScope(systemScope(tenantId), async (tx) => {
      await tx
        .update(kelpieCases)
        .set({ caseId: created.id, caseNumber: created.caseNumber, caseUrl: client.caseUrl(created.id), lastError: null, attempts: 0, pushedAt: now })
        .where(eq(kelpieCases.incidentId, row.incidentId));
      await tx.insert(incidentTimeline).values({
        tenantId, incidentId: row.incidentId, occurredAt: now, origin: "machine", category: "status",
        title: `Kelpie case ${created.caseNumber} ${created.created ? "opened" : "linked"}`, refType: "kelpie_case", refId: created.id,
      });
      await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "kelpie.case_push", targetType: "incident", targetId: row.incidentId, detail: { caseId: created.id, caseNumber: created.caseNumber, created: created.created } });
    });
    return true;
  } catch (err) {
    await failed(tenantId, row.incidentId, row.attempts, err, now);
    return false;
  }
}

/** Observables and playbook tasks go to the case once. Tasks arrive as comments: Kelpie owns task tracking. */
async function forward(client: KelpieClient, row: typeof kelpieCases.$inferSelect, now: Date): Promise<number> {
  const tenantId = row.tenantId;
  const caseId = row.caseId!;
  let sent = 0;
  if (!row.observablesPushedAt) {
    const obs = await withScope(systemScope(tenantId), (tx) =>
      tx.select({ refId: incidentLinks.refId, label: incidentLinks.label }).from(incidentLinks).where(and(eq(incidentLinks.incidentId, row.incidentId), eq(incidentLinks.kind, "observable"))));
    for (const o of obs) {
      const mapped = kelpieObservable(o.refId);
      if (mapped) await client.addObservable(caseId, { ...mapped, description: "From blakSOC detection", isIoc: true });
    }
    await withScope(systemScope(tenantId), (tx) => tx.update(kelpieCases).set({ observablesPushedAt: now }).where(eq(kelpieCases.incidentId, row.incidentId)));
  }
  const tasks = await withScope(systemScope(tenantId), (tx) =>
    tx.select().from(incidentTasks).where(and(eq(incidentTasks.incidentId, row.incidentId), isNull(incidentTasks.kelpieCommentId))).orderBy(asc(incidentTasks.createdAt)));
  for (const t of tasks) {
    const c = await client.addComment(caseId, `Task from a blakSOC playbook: ${t.title}`);
    await withScope(systemScope(tenantId), (tx) => tx.update(incidentTasks).set({ kelpieCommentId: c.id }).where(eq(incidentTasks.id, t.id)));
    sent++;
  }
  return sent;
}

/** Refresh our own evidence section after case status has been mirrored, so a failed write cannot block it. */
async function forwardDetectionContext(client: KelpieClient, row: typeof kelpieCases.$inferSelect) {
  const remote = await client.getCase(row.caseId!);
  const detections = await withScope(systemScope(row.tenantId), (tx) => incidentDetections(tx, row.incidentId));
  const summary = mergeDetectionContext(remote.summary, detectionContext(detections, env().APP_URL));
  if (summary !== (remote.summary ?? "")) {
    // Optimistic concurrency prevents overwriting an analyst's concurrent summary edit.
    if (summary.length > 50_000) throw new Error("Kelpie summary has no room for detection context; shorten the analyst summary.");
    await client.updateSummary(row.caseId!, summary, remote.version);
  }
}

/** Mirrors Kelpie's status, severity and title onto the incident so the portal, paging and breach clocks follow Kelpie. */
async function pull(client: KelpieClient, row: typeof kelpieCases.$inferSelect, now: Date): Promise<boolean> {
  const tenantId = row.tenantId;
  const remote = await client.getCase(row.caseId!);
  if (remote.version === row.version) {
    await withScope(systemScope(tenantId), (tx) => tx.update(kelpieCases).set({ syncedAt: now, lastError: null }).where(eq(kelpieCases.incidentId, row.incidentId)));
    return false;
  }
  const status = incidentStatusFor(remote.status);
  let changed = false;
  await withScope(systemScope(tenantId), async (tx) => {
    const [inc] = await tx.select().from(incidents).where(eq(incidents.id, row.incidentId));
    if (!inc) return;
    const patch: Partial<typeof incidents.$inferInsert> = {};
    if (status && status !== inc.status) {
      patch.status = status;
      if (status === "CONTAINED" && !inc.containedAt) patch.containedAt = now;
      if (status === "CLOSED") patch.closedAt = remote.closedAt ? new Date(remote.closedAt) : now;
    }
    // blakSOC's informational has no Kelpie equivalent; leave it alone while Kelpie says low.
    if (remote.severity !== inc.severity && !(inc.severity === "informational" && remote.severity === "low")) patch.severity = remote.severity;
    if (remote.title && remote.title !== inc.title) patch.title = remote.title;
    if (Object.keys(patch).length) {
      changed = true;
      await tx.update(incidents).set({ ...patch, updatedAt: now }).where(eq(incidents.id, inc.id));
      if (patch.status) {
        await tx.insert(incidentTimeline).values({ tenantId, incidentId: inc.id, occurredAt: now, origin: "machine", category: "status", title: `Status ${inc.status} → ${patch.status} (Kelpie ${remote.caseNumber})`, refType: "kelpie_case", refId: remote.id });
      }
      await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "kelpie.case_sync", targetType: "incident", targetId: inc.id, detail: { caseNumber: remote.caseNumber, version: remote.version, patch } });
    }
    await tx.update(kelpieCases).set({ version: remote.version, syncedAt: now, lastError: null }).where(eq(kelpieCases.incidentId, row.incidentId));
  });
  if (changed) await publish({ type: "incident.updated", tenantId, id: row.incidentId }).catch(() => {});
  return changed;
}

/**
 * One pass for every tenant with Kelpie: queue open incidents, push new cases, forward observables and playbook
 * tasks, then mirror case changes back. Each incident is handled on its own, so one failure never blocks the rest.
 */
export async function syncKelpie(opts: { now?: Date; connect?: KelpieConnect; limit?: number } = {}): Promise<Counts> {
  const now = opts.now ?? new Date();
  const connect = opts.connect ?? defaultConnect;
  const limit = opts.limit ?? 200;
  const counts: Counts = { queued: 0, pushed: 0, failed: 0, synced: 0, forwarded: 0 };
  const rows = await systemDb().select().from(integrations).where(and(eq(integrations.provider, "kelpie"), eq(integrations.enabled, true)));
  for (const integration of rows) {
    const tenantId = integration.tenantId;
    if (!tenantId) continue;
    const [gov] = await systemDb().select({ profile: dataGovernance.profile }).from(dataGovernance).where(eq(dataGovernance.tenantId, tenantId));
    if (!checkGovernedRegion(gov?.profile ?? MOST_PROTECTIVE, integration.config.region).allowed) continue;
    let client: KelpieClient;
    try {
      client = connect(integration);
    } catch {
      continue;
    }
    const [tenant] = await systemDb().select({ slug: tenants.slug }).from(tenants).where(eq(tenants.id, tenantId));

    // Queue open incidents that have no link yet. Closed incidents are history and stay in blakSOC.
    counts.queued += await withScope(systemScope(tenantId), async (tx) => {
      const open = await tx
        .select({ id: incidents.id })
        .from(incidents)
        .leftJoin(kelpieCases, eq(kelpieCases.incidentId, incidents.id))
        .where(and(eq(incidents.tenantId, tenantId), ne(incidents.status, "CLOSED"), isNull(kelpieCases.incidentId)))
        .limit(limit);
      if (open.length) await tx.insert(kelpieCases).values(open.map((o) => ({ incidentId: o.id, tenantId, integrationId: integration.id, nextAttemptAt: now }))).onConflictDoNothing();
      return open.length;
    });

    const due = await withScope(systemScope(tenantId), (tx) =>
      tx.select().from(kelpieCases).where(and(eq(kelpieCases.tenantId, tenantId), isNull(kelpieCases.caseId), lte(kelpieCases.nextAttemptAt, now))).limit(limit));
    for (const row of due) {
      if (await pushCase(client, row, tenant?.slug ?? "unknown", now)) counts.pushed++;
      else counts.failed++;
    }

    const linked = await withScope(systemScope(tenantId), (tx) =>
      tx
        .select({ link: kelpieCases })
        .from(kelpieCases)
        .innerJoin(incidents, eq(incidents.id, kelpieCases.incidentId))
        .where(and(eq(kelpieCases.tenantId, tenantId), ne(incidents.status, "CLOSED"), lte(kelpieCases.nextAttemptAt, now)))
        .limit(limit));
    for (const { link } of linked) {
      if (!link.caseId) continue;
      try {
        counts.forwarded += await forward(client, link, now);
        if (await pull(client, link, now)) counts.synced++;
        await forwardDetectionContext(client, link);
      } catch (err) {
        counts.failed++;
        const permanent = err instanceof KelpieError && err.permanent;
        await withScope(systemScope(tenantId), (tx) =>
          tx.update(kelpieCases).set({ lastError: message(err), ...(permanent ? { attempts: link.attempts + 1, nextAttemptAt: backoff(link.attempts + 1, now) } : {}) }).where(eq(kelpieCases.incidentId, link.incidentId)));
      }
    }
  }
  return counts;
}

/** Links shown on incident pages. */
export async function kelpieLinksFor(tx: DbOrTx, incidentIds: string[]) {
  if (!incidentIds.length) return [];
  return tx.select().from(kelpieCases).where(inArray(kelpieCases.incidentId, incidentIds));
}
