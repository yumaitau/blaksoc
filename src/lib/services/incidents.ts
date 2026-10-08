import { and, asc, desc, eq, inArray, isNull, ne, or, sql, type SQL } from "drizzle-orm";
import type { Tx } from "@/db/client";
import {
  alerts, approvals, assets, evidence, incidentAlerts, incidentGroupExclusions, incidentLinks, incidentNotes, incidents, incidentTasks, incidentTimeline,
  responseActions, roleAssignments, roles, tenants, user, type TenantSettings,
} from "@/db/schema";
import { can, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { publish } from "@/lib/events";
import { queue, QUEUES } from "@/lib/queue";
import { actor, AccessDenied, inTenant, scoped, userRef } from "./common";
import { assertNotKelpieManaged, kelpieIntegration, kelpieLink } from "./kelpie";
import { incidentDetections } from "./incident-context";

export const INCIDENT_STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
const SEV_RANK = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

export async function listIncidents(ctx: AccessContext, f: { tenantIds?: string[]; status?: IncidentStatus[]; open?: boolean; owner?: "me"; limit?: number } = {}) {
  return scoped(
    ctx,
    "incident:read",
    async (tx, tenantIds) => {
      const where: SQL[] = [inArray(incidents.tenantId, tenantIds)];
      if (f.status?.length) where.push(inArray(incidents.status, f.status));
      if (f.open) where.push(ne(incidents.status, "CLOSED"));
      if (f.owner === "me") where.push(eq(incidents.ownerId, ctx.principal.userId));
      return tx
        .select({
          id: incidents.id, ref: incidents.ref, tenantId: incidents.tenantId, tenantName: tenants.name, title: incidents.title, severity: incidents.severity,
          status: incidents.status, riskScore: incidents.riskScore, ownerName: user.name, createdAt: incidents.createdAt, updatedAt: incidents.updatedAt,
          slaDueAt: incidents.slaDueAt, attackTechniques: incidents.attackTechniques,
          alertCount: sql<number>`(select count(*)::int from ${incidentAlerts} where ${incidentAlerts.incidentId} = ${incidents.id})`,
        })
        .from(incidents)
        .innerJoin(tenants, eq(tenants.id, incidents.tenantId))
        .leftJoin(user, eq(user.id, incidents.ownerId))
        .where(and(...where))
        .orderBy(desc(incidents.updatedAt))
        .limit(f.limit ?? 200);
    },
    f.tenantIds,
  );
}

export async function getIncident(ctx: AccessContext, id: string) {
  return scoped(ctx, "incident:read", async (tx, tenantIds) => {
    const [row] = await tx
      .select({ incident: incidents, tenantName: tenants.name, ownerName: user.name })
      .from(incidents)
      .innerJoin(tenants, eq(tenants.id, incidents.tenantId))
      .leftJoin(user, eq(user.id, incidents.ownerId))
      .where(and(eq(incidents.id, id), inArray(incidents.tenantId, tenantIds)));
    if (!row) return null;
    const soc = can(ctx, "alert:triage", row.incident.tenantId);
    const [alertRows, links, timeline, notes, tasks, ev, actions, pending] = await Promise.all([
      tx
        .select({ id: alerts.id, title: alerts.title, severity: alerts.severity, riskScore: alerts.riskScore, status: alerts.status, occurredAt: alerts.occurredAt, assetName: assets.name, userName: alerts.userName, intelVerdict: alerts.intelVerdict, attackTechniques: alerts.attackTechniques, origin: incidentAlerts.origin, groupReason: incidentAlerts.reason })
        .from(incidentAlerts)
        .innerJoin(alerts, eq(alerts.id, incidentAlerts.alertId))
        .leftJoin(assets, eq(assets.id, alerts.assetId))
        .where(eq(incidentAlerts.incidentId, id))
        .orderBy(asc(alerts.occurredAt)),
      tx.select().from(incidentLinks).where(eq(incidentLinks.incidentId, id)),
      tx.select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, id)).orderBy(asc(incidentTimeline.occurredAt)),
      tx
        .select({ id: incidentNotes.id, body: incidentNotes.body, visibility: incidentNotes.visibility, aiGenerated: incidentNotes.aiGenerated, createdAt: incidentNotes.createdAt, authorName: user.name })
        .from(incidentNotes)
        .leftJoin(user, eq(user.id, incidentNotes.authorId))
        .where(and(eq(incidentNotes.incidentId, id), soc ? sql`true` : eq(incidentNotes.visibility, "customer")))
        .orderBy(desc(incidentNotes.createdAt)),
      tx.select().from(incidentTasks).where(eq(incidentTasks.incidentId, id)).orderBy(asc(incidentTasks.createdAt)),
      tx.select().from(evidence).where(eq(evidence.incidentId, id)).orderBy(desc(evidence.collectedAt)),
      tx.select().from(responseActions).where(eq(responseActions.incidentId, id)).orderBy(desc(responseActions.createdAt)),
      tx.select().from(approvals).where(and(eq(approvals.tenantId, row.incident.tenantId), eq(approvals.status, "PENDING"))),
    ]);
    const actionIds = new Set(actions.map((a) => a.approvalId));
    const managed = !!(await kelpieIntegration(tx, row.incident.tenantId));
    return {
      ...row,
      kelpie: { managed, link: managed ? await kelpieLink(tx, id) : null },
      alerts: alertRows,
      detections: soc ? await incidentDetections(tx, id) : [],
      links,
      timeline: soc ? timeline : timeline.filter((t) => t.origin !== "ai"),
      notes,
      tasks,
      evidence: ev,
      actions,
      pendingApprovals: pending.filter((p) => actionIds.has(p.id)),
    };
  });
}

async function tenantSettings(tx: Tx, tenantId: string): Promise<TenantSettings> {
  const [t] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, tenantId));
  return t!.settings;
}

/** Alert → Incident and Multiple Alerts → Incident. All alerts must belong to one tenant. */
export async function createIncidentFromAlerts(
  ctx: AccessContext | null,
  input: { tenantId: string; alertIds: string[]; title?: string; description?: string; ownerId?: string | null; actorKind?: "playbook" | "system" },
  txOverride?: Tx,
) {
  const run = async (tx: Tx) => {
    const rows = await tx.select().from(alerts).where(and(inArray(alerts.id, input.alertIds), eq(alerts.tenantId, input.tenantId)));
    if (rows.length !== input.alertIds.length) throw new AccessDenied("alerts must all belong to the incident's tenant");
    const top = rows.reduce((a, b) => (SEV_RANK[b.severity] > SEV_RANK[a.severity] ? b : a));
    const settings = await tenantSettings(tx, input.tenantId);
    const slaKey = (top.severity === "informational" ? "low" : top.severity) as keyof TenantSettings["slaMinutes"];
    const title = input.title ?? (rows.length === 1 ? top.title : `${top.title} (+${rows.length - 1} related)`);
    const techniques = [...new Set(rows.flatMap((r) => r.attackTechniques))];

    const [inc] = await tx
      .insert(incidents)
      .values({
        tenantId: input.tenantId,
        title,
        description: input.description ?? null,
        severity: top.severity,
        ownerId: input.ownerId ?? ctx?.principal.userId ?? null,
        attackTechniques: techniques,
        riskScore: Math.max(...rows.map((r) => r.riskScore)),
        slaDueAt: new Date(Date.now() + settings.slaMinutes[slaKey] * 60_000),
      })
      .returning();
    const incident = inc!;
    await linkAlerts(tx, incident.id, input.tenantId, rows);
    await addTimeline(tx, { tenantId: input.tenantId, incidentId: incident.id, origin: ctx ? "analyst" : "machine", category: "status", title: "Incident opened", actorId: ctx?.principal.userId ?? null });
    await audit(tx, { actorId: ctx?.principal.userId ?? null, actorKind: ctx ? "user" : (input.actorKind ?? "playbook"), tenantId: input.tenantId, action: "incident.create", targetType: "incident", targetId: incident.id, detail: { alertIds: input.alertIds } });
    return incident;
  };
  const incident = txOverride ? await run(txOverride) : ctx ? await inTenant(ctx, "incident:write", input.tenantId, run) : (() => { throw new Error("system callers must pass a transaction"); })();
  await publish({ type: "incident.created", tenantId: input.tenantId, id: incident.id, title: incident.title, severity: incident.severity });
  // Push to Kelpie now rather than on the next minute tick. The job id collapses bursts into one run.
  await queue(QUEUES.sync).add("kelpie", {}, { jobId: `kelpie-${Math.floor(Date.now() / 5000)}` }).catch(() => {});
  return incident;
}

export async function linkAlerts(tx: Tx, incidentId: string, tenantId: string, rows: (typeof alerts.$inferSelect)[]) {
  for (const a of rows) {
    await tx.insert(incidentAlerts).values({ tenantId, incidentId, alertId: a.id }).onConflictDoNothing();
    await tx.update(alerts).set({ incidentId, status: a.status === "NEW" || a.status === "TRIAGING" ? "ESCALATED" : a.status }).where(eq(alerts.id, a.id));
    await addTimeline(tx, { tenantId, incidentId, occurredAt: a.occurredAt, origin: "machine", category: "detection", title: a.title, detail: a.userName ? `User ${a.userName}` : null, refType: "alert", refId: a.id });
    for (const m of a.intel?.matches ?? []) {
      if (m.verdict === "benign") continue;
      await addTimeline(tx, { tenantId, incidentId, occurredAt: a.ingestedAt, origin: "machine", category: "intel", title: `OpenCTI match: ${m.observable.value}`, detail: `${m.verdict} · ${m.source ?? "OpenCTI"}${m.malware.length ? ` · ${m.malware.join(", ")}` : ""}`, refType: "opencti", refId: m.openctiId });
      await tx.insert(incidentLinks).values({ tenantId, incidentId, kind: "intel", refId: m.openctiId, label: `${m.observable.value} (${m.verdict})`, data: m }).onConflictDoNothing();
      await tx.insert(incidentLinks).values({ tenantId, incidentId, kind: "observable", refId: `${m.observable.type}:${m.observable.value}`, label: m.observable.value }).onConflictDoNothing();
    }
    if (a.assetId) {
      const [asset] = await tx.select({ name: assets.name }).from(assets).where(eq(assets.id, a.assetId));
      await tx.insert(incidentLinks).values({ tenantId, incidentId, kind: "asset", refId: a.assetId, label: asset?.name ?? a.assetId }).onConflictDoNothing();
    }
    if (a.userName) await tx.insert(incidentLinks).values({ tenantId, incidentId, kind: "identity", refId: a.userName.toLowerCase(), label: a.userName }).onConflictDoNothing();
  }
}

/** Incident links an alert would add (see linkAlerts). */
function linksOf(a: typeof alerts.$inferSelect): string[] {
  const out: string[] = [];
  for (const m of a.intel?.matches ?? []) {
    if (m.verdict === "benign") continue;
    out.push(`intel:${m.openctiId}`, `observable:${m.observable.type}:${m.observable.value}`);
  }
  if (a.assetId) out.push(`asset:${a.assetId}`);
  if (a.userName) out.push(`identity:${a.userName.toLowerCase()}`);
  return out;
}

/**
 * Undo automatic grouping for some or all of an incident's auto-linked alerts: drop the links, give each alert back
 * the status grouping replaced (unless an analyst has moved it since), remove incident links only those alerts
 * brought, and keep grouping away from them from now on. An incident grouping opened closes once it is empty.
 */
export async function ungroupAlerts(ctx: AccessContext, incidentId: string, alertIds?: string[]) {
  const inc = await getIncidentHead(ctx, incidentId);
  const result = await inTenant(ctx, "incident:write", inc.tenantId, async (tx) => {
    const where = [eq(incidentAlerts.incidentId, incidentId), eq(incidentAlerts.origin, "auto")];
    if (alertIds?.length) where.push(inArray(incidentAlerts.alertId, alertIds));
    const links = await tx.select().from(incidentAlerts).where(and(...where));
    if (!links.length || (alertIds?.length && links.length !== new Set(alertIds).size)) throw new AccessDenied("only automatically grouped alerts can be ungrouped");
    const ids = links.map((l) => l.alertId);
    await tx.delete(incidentAlerts).where(and(eq(incidentAlerts.incidentId, incidentId), inArray(incidentAlerts.alertId, ids)));

    const removed = await tx.select().from(alerts).where(inArray(alerts.id, ids)).orderBy(asc(alerts.occurredAt));
    const now = new Date();
    for (const a of removed) {
      const prior = links.find((l) => l.alertId === a.id)!.priorStatus;
      const [other] = await tx.select({ incidentId: incidentAlerts.incidentId }).from(incidentAlerts).where(eq(incidentAlerts.alertId, a.id)).limit(1);
      await tx
        .update(alerts)
        .set({ status: a.status === "ESCALATED" && prior ? prior : a.status, incidentId: a.incidentId === incidentId ? (other?.incidentId ?? null) : a.incidentId, updatedAt: now })
        .where(eq(alerts.id, a.id));
      await tx
        .insert(incidentGroupExclusions)
        .values({ alertId: a.id, tenantId: inc.tenantId, incidentId, actorId: ctx.principal.userId })
        .onConflictDoUpdate({ target: incidentGroupExclusions.alertId, set: { incidentId, actorId: ctx.principal.userId, createdAt: now } });
    }

    const remaining = await tx.select().from(alerts).innerJoin(incidentAlerts, eq(incidentAlerts.alertId, alerts.id)).where(eq(incidentAlerts.incidentId, incidentId));
    const kept = new Set(remaining.flatMap((r) => linksOf(r.alerts)));
    for (const key of new Set(removed.flatMap(linksOf))) {
      if (kept.has(key)) continue;
      const [kind, ...rest] = key.split(":");
      await tx.delete(incidentLinks).where(and(eq(incidentLinks.incidentId, incidentId), eq(incidentLinks.kind, kind!), eq(incidentLinks.refId, rest.join(":"))));
    }

    await addTimeline(tx, {
      tenantId: inc.tenantId, incidentId, origin: "analyst", category: "grouping", actorId: ctx.principal.userId,
      title: `Ungrouped ${ids.length} alert${ids.length === 1 ? "" : "s"}`, detail: removed.map((a) => a.title).join("; "),
    });
    // Kelpie owns status for a connected tenant; the case there is closed by the analyst.
    const close = !!inc.groupingKey && remaining.length === 0 && inc.status !== "CLOSED" && !(await kelpieIntegration(tx, inc.tenantId));
    await tx.update(incidents).set({ updatedAt: now, ...(close ? { status: "CLOSED" as const, closedAt: now } : {}) }).where(eq(incidents.id, incidentId));
    if (close) {
      await addTimeline(tx, { tenantId: inc.tenantId, incidentId, origin: "analyst", category: "status", title: `Status ${inc.status} → CLOSED`, detail: "Every alert automatic grouping added was ungrouped.", actorId: ctx.principal.userId });
    }
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "incident.ungroup", targetType: "incident", targetId: incidentId, detail: { alertIds: ids, closed: close } });
    return { alertIds: ids, closed: close };
  });
  await publish({ type: "incident.updated", tenantId: inc.tenantId, id: incidentId });
  return result;
}

export async function addAlertsToIncident(ctx: AccessContext, incidentId: string, alertIds: string[]) {
  const inc = await getIncidentHead(ctx, incidentId);
  return inTenant(ctx, "incident:write", inc.tenantId, async (tx) => {
    const rows = await tx.select().from(alerts).where(and(inArray(alerts.id, alertIds), eq(alerts.tenantId, inc.tenantId)));
    if (rows.length !== alertIds.length) throw new AccessDenied("alerts must belong to the incident's tenant");
    await linkAlerts(tx, incidentId, inc.tenantId, rows);
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "incident.add_alerts", targetType: "incident", targetId: incidentId, detail: { alertIds } });
  });
}

export async function addTimeline(
  tx: Tx,
  e: { tenantId: string; incidentId: string; occurredAt?: Date; origin: "machine" | "analyst" | "ai" | "customer"; category: string; title: string; detail?: string | null; actorId?: string | null; refType?: string; refId?: string },
) {
  await tx.insert(incidentTimeline).values({ ...e, occurredAt: e.occurredAt ?? new Date(), detail: e.detail ?? null, actorId: e.actorId ?? null });
}

async function getIncidentHead(ctx: AccessContext, id: string) {
  const inc = await scoped(ctx, "incident:read", async (tx, tenantIds) => (await tx.select().from(incidents).where(and(eq(incidents.id, id), inArray(incidents.tenantId, tenantIds))))[0]);
  if (!inc) throw new AccessDenied("incident not found");
  return inc;
}

export type IncidentPatch = Partial<Pick<typeof incidents.$inferInsert, "title" | "description" | "severity" | "status" | "ownerId" | "containment" | "remediation" | "rootCause" | "lessonsLearned" | "collaboratorIds">>;

export async function updateIncident(ctx: AccessContext, id: string, patch: IncidentPatch) {
  const inc = await getIncidentHead(ctx, id);
  const perm = patch.status === "CLOSED" ? "incident:close" : "incident:write";
  return inTenant(ctx, perm, inc.tenantId, async (tx) => {
    await assertNotKelpieManaged(tx, inc.tenantId, id);
    const now = new Date();
    await tx
      .update(incidents)
      .set({
        ...patch,
        updatedAt: now,
        ...(patch.status === "CONTAINED" && !inc.containedAt ? { containedAt: now } : {}),
        ...(patch.status === "CLOSED" ? { closedAt: now } : {}),
      })
      .where(eq(incidents.id, id));
    if (patch.status && patch.status !== inc.status) {
      await addTimeline(tx, { tenantId: inc.tenantId, incidentId: id, origin: "analyst", category: "status", title: `Status ${inc.status} → ${patch.status}`, actorId: ctx.principal.userId });
    }
    if (patch.ownerId !== undefined && patch.ownerId !== inc.ownerId) {
      const [owner] = patch.ownerId ? await tx.select({ name: user.name }).from(user).where(eq(user.id, patch.ownerId)) : [];
      await addTimeline(tx, { tenantId: inc.tenantId, incidentId: id, origin: "analyst", category: "analyst", title: owner ? `Assigned to ${owner.name}` : "Unassigned", actorId: ctx.principal.userId });
    }
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "incident.update", targetType: "incident", targetId: id, detail: { patch } });
    await publish({ type: "incident.updated", tenantId: inc.tenantId, id });
  });
}

export async function addNote(ctx: AccessContext, incidentId: string, body: string, visibility: "internal" | "customer", aiGenerated = false) {
  const inc = await getIncidentHead(ctx, incidentId);
  return inTenant(ctx, "incident:write", inc.tenantId, async (tx) => {
    // Customer notes feed the portal and stay in blakSOC. Internal case notes belong in Kelpie.
    if (visibility === "internal") await assertNotKelpieManaged(tx, inc.tenantId, incidentId);
    const [n] = await tx.insert(incidentNotes).values({ tenantId: inc.tenantId, incidentId, authorId: userRef(ctx), body, visibility, aiGenerated }).returning();
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "incident.note", targetType: "incident", targetId: incidentId, detail: { noteId: n!.id, visibility, aiGenerated } });
    return n!;
  });
}

export async function addAnalystTimelineEvent(ctx: AccessContext, incidentId: string, e: { occurredAt: Date; title: string; detail?: string }) {
  const inc = await getIncidentHead(ctx, incidentId);
  return inTenant(ctx, "incident:write", inc.tenantId, async (tx) => {
    await assertNotKelpieManaged(tx, inc.tenantId, incidentId);
    await addTimeline(tx, { tenantId: inc.tenantId, incidentId, occurredAt: e.occurredAt, origin: "analyst", category: "analyst", title: e.title, detail: e.detail ?? null, actorId: ctx.principal.userId });
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "incident.timeline_add", targetType: "incident", targetId: incidentId, detail: e });
  });
}

/** Customer confirmation that they have read the incident. Stops further escalation. */
export async function acknowledgeIncident(ctx: AccessContext, incidentId: string) {
  const inc = await getIncidentHead(ctx, incidentId);
  if (!can(ctx, "portal:read", inc.tenantId)) throw new AccessDenied("missing portal:read");
  return inTenant(ctx, "incident:read", inc.tenantId, async (tx) => {
    const [existing] = await tx
      .select({ occurredAt: incidentTimeline.occurredAt })
      .from(incidentTimeline)
      .where(and(eq(incidentTimeline.incidentId, incidentId), eq(incidentTimeline.category, "acknowledgement")))
      .limit(1);
    if (existing) return { already: true as const, at: existing.occurredAt };
    await addTimeline(tx, {
      tenantId: inc.tenantId,
      incidentId,
      origin: "customer",
      category: "acknowledgement",
      title: "I've read this",
      detail: "The customer confirmed they have read this incident.",
      actorId: ctx.principal.userId,
    });
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "incident.acknowledge", targetType: "incident", targetId: incidentId });
    return { already: false as const };
  });
}

export async function addTask(ctx: AccessContext, incidentId: string, title: string) {
  const inc = await getIncidentHead(ctx, incidentId);
  return inTenant(ctx, "incident:write", inc.tenantId, async (tx) => {
    await assertNotKelpieManaged(tx, inc.tenantId, incidentId);
    return tx.insert(incidentTasks).values({ tenantId: inc.tenantId, incidentId, title }).returning();
  });
}

export async function toggleTask(ctx: AccessContext, taskId: string, done: boolean) {
  return scoped(ctx, "incident:write", async (tx, tenantIds) => {
    const [found] = await tx.select({ tenantId: incidentTasks.tenantId, incidentId: incidentTasks.incidentId }).from(incidentTasks).where(and(eq(incidentTasks.id, taskId), inArray(incidentTasks.tenantId, tenantIds)));
    if (found) await assertNotKelpieManaged(tx, found.tenantId, found.incidentId);
    const [t] = await tx.update(incidentTasks).set({ done }).where(and(eq(incidentTasks.id, taskId), inArray(incidentTasks.tenantId, tenantIds))).returning();
    if (!t) throw new AccessDenied("task not found");
    return t;
  });
}

export async function addEvidence(ctx: AccessContext, incidentId: string, e: { name: string; kind: string; sha256?: string; storageUri?: string; description?: string }) {
  const inc = await getIncidentHead(ctx, incidentId);
  return inTenant(ctx, "incident:write", inc.tenantId, async (tx) => {
    const [row] = await tx.insert(evidence).values({ tenantId: inc.tenantId, incidentId, ...e, collectedBy: ctx.principal.name }).returning();
    await addTimeline(tx, { tenantId: inc.tenantId, incidentId, origin: "analyst", category: "analyst", title: `Evidence added: ${e.name}`, detail: e.sha256 ? `sha256 ${e.sha256}` : null, actorId: ctx.principal.userId, refType: "evidence", refId: row!.id });
    await audit(tx, { ...actor(ctx), tenantId: inc.tenantId, action: "incident.evidence_add", targetType: "incident", targetId: incidentId, detail: { evidenceId: row!.id, name: e.name, sha256: e.sha256 } });
    return row!;
  });
}

/** People who can own an incident in this tenant: anyone holding incident:write there (platform roles included). */
export async function listIncidentOwners(ctx: AccessContext, tenantId: string) {
  if (!can(ctx, "incident:read", tenantId)) throw new AccessDenied("missing incident:read");
  const { db } = await import("@/db/client");
  // role_assignments/roles/user carry no RLS; the tenant filter below is the scope.
  return db()
    .selectDistinct({ id: user.id, name: user.name })
    .from(roleAssignments)
    .innerJoin(roles, eq(roles.key, roleAssignments.roleKey))
    .innerJoin(user, eq(user.id, roleAssignments.userId))
    .where(and(
      or(isNull(roleAssignments.tenantId), eq(roleAssignments.tenantId, tenantId)),
      sql`'incident:write' = any(${roles.permissions})`,
      eq(user.disabled, false),
    ))
    .orderBy(user.name);
}
