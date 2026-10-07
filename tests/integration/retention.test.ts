/**
 * Alert retention: severity tiers, incident-linked alerts kept, graph nodes and evidence removed with the
 * alert, an audit row per purge, and other tenants untouched.
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, auditLog, entities, entityRelationshipEvidence, entityRelationships, incidents, tenants } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { redis } from "@/lib/redis";
import { ALERT_RETENTION_DAYS, purgeTenantAlerts } from "@/lib/services/retention";

const run = randomUUID().slice(0, 8);
const now = new Date();
const DAY = 86_400_000;
let tenantA = "";
let tenantB = "";
const ids: Record<string, string> = {};

async function alert(tenantId: string, key: string, severity: "informational" | "medium" | "high", daysAgo: number, incidentId: string | null = null) {
  const [row] = await adminDb()
    .insert(alerts)
    .values({ tenantId, source: "retention-test", externalId: `${key}-${run}`, title: key, severity, occurredAt: new Date(now.getTime() - daysAgo * DAY), incidentId } as never)
    .returning({ id: alerts.id });
  ids[key] = row!.id;
  return row!.id;
}

beforeAll(async () => {
  const make = (name: string) => adminDb().insert(tenants).values({ name, slug: `ret-${name}-${run}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  tenantA = (await make("a"))[0]!.id;
  tenantB = (await make("b"))[0]!.id;
  const [inc] = await adminDb().insert(incidents).values({ tenantId: tenantA, title: "Kept case", severity: "high" }).returning();

  await alert(tenantA, "info-old", "informational", ALERT_RETENTION_DAYS.informational + 5);
  await alert(tenantA, "info-new", "informational", ALERT_RETENTION_DAYS.informational - 5);
  await alert(tenantA, "medium-old", "medium", ALERT_RETENTION_DAYS.medium + 5);
  await alert(tenantA, "medium-new", "medium", ALERT_RETENTION_DAYS.medium - 5);
  await alert(tenantA, "high-old", "high", ALERT_RETENTION_DAYS.high + 5);
  await alert(tenantA, "high-old-in-case", "high", ALERT_RETENTION_DAYS.high + 5, inc!.id);
  await alert(tenantB, "other-tenant-old", "informational", ALERT_RETENTION_DAYS.informational + 5);

  // Graph: the old informational alert as a node linked to a host, with evidence pointing at it.
  const [node] = await adminDb().insert(entities).values({ tenantId: tenantA, type: "alert", key: ids["info-old"]!, displayName: "info-old" } as never).returning();
  const [host] = await adminDb().insert(entities).values({ tenantId: tenantA, type: "device", key: `host-${run}`, displayName: "host" } as never).returning();
  const [edge] = await adminDb()
    .insert(entityRelationships)
    .values({ tenantId: tenantA, fromEntityId: node!.id, toEntityId: host!.id, type: "alerted_on", provenance: "observed", evidenceType: "alert", evidenceId: ids["info-old"]! } as never)
    .returning();
  await adminDb().insert(entityRelationshipEvidence).values({ relationshipId: edge!.id, tenantId: tenantA, evidenceType: "alert", evidenceId: ids["info-old"]!, observedAt: now });

  // Edges between non-alert entities that the purged alert vouched for.
  const [user] = await adminDb().insert(entities).values({ tenantId: tenantA, type: "user", key: `kim-${run}`, displayName: "kim" } as never).returning();
  const [onlyAlert] = await adminDb()
    .insert(entityRelationships)
    .values({ tenantId: tenantA, fromEntityId: user!.id, toEntityId: host!.id, type: "logged_into", provenance: "observed", count: 1, evidenceType: "alert", evidenceId: ids["medium-old"]! } as never)
    .returning();
  await adminDb().insert(entityRelationshipEvidence).values({ relationshipId: onlyAlert!.id, tenantId: tenantA, evidenceType: "alert", evidenceId: ids["medium-old"]!, observedAt: now });
  const [mixed] = await adminDb()
    .insert(entityRelationships)
    .values({ tenantId: tenantA, fromEntityId: host!.id, toEntityId: user!.id, type: "used_by", provenance: "inferred", count: 2, evidenceType: "alert", evidenceId: ids["high-old"]! } as never)
    .returning();
  await adminDb().insert(entityRelationshipEvidence).values([
    { relationshipId: mixed!.id, tenantId: tenantA, evidenceType: "asset", evidenceId: "asset-1", observedAt: new Date(now.getTime() - DAY) },
    { relationshipId: mixed!.id, tenantId: tenantA, evidenceType: "alert", evidenceId: ids["high-old"]!, observedAt: now },
  ]);
  ids.mixedEdge = mixed!.id;
});

afterAll(async () => {
  for (const id of [tenantA, tenantB].filter(Boolean)) await adminDb().delete(tenants).where(eq(tenants.id, id));
  await redis().quit();
});

describe("alert retention", () => {
  it("removes alerts past their severity's retention and keeps the rest", async () => {
    const counts = await purgeTenantAlerts(tenantA, now);
    expect(counts).toEqual({ informational: 1, medium: 1, high: 1 });
    const left = (await adminDb().select({ title: alerts.title }).from(alerts).where(inArray(alerts.tenantId, [tenantA, tenantB]))).map((r) => r.title).sort();
    expect(left).toEqual(["high-old-in-case", "info-new", "medium-new", "other-tenant-old"]);
  });

  it("removes the purged alert's graph node and the edges only it vouched for, and repoints the rest", async () => {
    expect(await adminDb().select().from(entities).where(and(eq(entities.tenantId, tenantA), eq(entities.type, "alert")))).toEqual([]);
    const edges = await adminDb().select().from(entityRelationships).where(eq(entityRelationships.tenantId, tenantA));
    expect(edges.map((e) => e.type)).toEqual(["used_by"]);
    expect(edges[0]).toMatchObject({ id: ids.mixedEdge, count: 1, evidenceType: "asset", evidenceId: "asset-1" });
    const evidence = await adminDb().select().from(entityRelationshipEvidence).where(eq(entityRelationshipEvidence.tenantId, tenantA));
    expect(evidence.map((e) => e.evidenceType)).toEqual(["asset"]);
    expect(await adminDb().select().from(entities).where(and(eq(entities.tenantId, tenantA), eq(entities.type, "device")))).toHaveLength(1);
  });

  it("audits each batch with its counts, and does nothing on a second run", async () => {
    const audits = () => adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenantA), eq(auditLog.action, "retention.purge_alerts")));
    const rows = await audits();
    expect(rows.map((r) => (r.detail as { severity: string }).severity).sort()).toEqual(["high", "informational", "medium"]);
    expect(rows.every((r) => (r.detail as { deleted: number }).deleted === 1)).toBe(true);
    expect(await purgeTenantAlerts(tenantA, now)).toEqual({});
    expect(await audits()).toHaveLength(3);
  });
});
