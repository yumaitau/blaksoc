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

  it("removes the purged alert's graph node, its edges and evidence", async () => {
    expect(await adminDb().select().from(entities).where(and(eq(entities.tenantId, tenantA), eq(entities.type, "alert")))).toEqual([]);
    expect(await adminDb().select().from(entityRelationships).where(eq(entityRelationships.tenantId, tenantA))).toEqual([]);
    expect(await adminDb().select().from(entityRelationshipEvidence).where(eq(entityRelationshipEvidence.tenantId, tenantA))).toEqual([]);
    expect(await adminDb().select().from(entities).where(and(eq(entities.tenantId, tenantA), eq(entities.type, "device")))).toHaveLength(1);
  });

  it("audits the purge with its counts, and does nothing on a second run", async () => {
    const rows = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenantA), eq(auditLog.action, "retention.purge_alerts")));
    expect(rows).toHaveLength(1);
    expect(rows[0]!.detail).toMatchObject({ deleted: { informational: 1, medium: 1, high: 1 } });
    expect(await purgeTenantAlerts(tenantA, now)).toEqual({});
    expect(await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenantA), eq(auditLog.action, "retention.purge_alerts")))).toHaveLength(1);
  });
});
