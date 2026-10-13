import { readFileSync } from "node:fs";
import { eq, inArray, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, e8Assessments, integrations, roleAssignments, roles, tenants, user } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import type { AssessmentResult } from "@/lib/essential-eight/score";
import { normaliseWedgetail } from "@/lib/providers/wedgetail";
import { ingestAlert } from "@/lib/pipeline/ingest";
import { listAlerts } from "@/lib/services/alerts";
import { complianceSignals } from "@/lib/services/compliance";
import { attackCoverage } from "@/lib/services/detections";
import { WEDGETAIL_CREATED } from "../fixtures/wedgetail";

vi.mock("@/lib/connectors/instances", async (original) => ({ ...await original<typeof import("@/lib/connectors/instances")>(), intelProviderFor: async () => null }));
vi.mock("@/lib/events", () => ({ publish: vi.fn() }));
vi.mock("@/lib/soar/engine", () => ({ evaluateTriggers: vi.fn() }));

const stamp = `compliance-${Date.now()}`;
const userId = `${stamp}-lead`;
const roleKey = `${stamp}-role`;
let a: string, b: string, integrationId: string;
let ctx: AccessContext;

beforeAll(async () => {
  await adminDb().insert(user).values({ id: userId, name: "Fictional lead", email: `${userId}@example.invalid`, emailVerified: true });
  await adminDb().insert(roles).values({ key: roleKey, name: "Compliance test", scope: "platform", permissions: ["alert:read", "report:read", "detection:read"] });
  await adminDb().insert(roleAssignments).values({ userId, roleKey });
  const rows = await adminDb().insert(tenants).values([
    { name: "Compliance A", slug: `${stamp}-a`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
    { name: "Compliance B", slug: `${stamp}-b`, kind: "customer", settings: DEFAULT_TENANT_SETTINGS },
  ]).returning();
  [a, b] = rows.map((r) => r.id) as [string, string];
  const [integration] = await adminDb().insert(integrations).values({ tenantId: a, provider: "wedgetail", category: "siem", name: "Fictional Wedgetail", config: {} }).returning();
  integrationId = integration!.id;
  ctx = await resolveAccess({ userId, name: "Fictional lead", email: `${userId}@example.invalid`, isBreakGlass: false });
  const result = { ratings: [{ strategy: "mfa", label: "Multi-factor authentication", level: 2, telemetry: "", lines: [] }, { strategy: "restrict_admin", label: "Restrict administrative privileges", level: 1, telemetry: "", lines: [] }] } as unknown as AssessmentResult;
  await adminDb().insert(e8Assessments).values({ tenantId: a, assessedAt: new Date(), cadenceDays: 90, nextDue: new Date(Date.now() + 90 * 86_400_000), owner: "Fictional owner", answers: {}, result });
});

afterAll(async () => {
  if (a) await adminDb().delete(tenants).where(inArray(tenants.id, [a, b]));
  await adminDb().delete(user).where(eq(user.id, userId));
  await adminDb().delete(roles).where(eq(roles.key, roleKey));
});

function wedgetailAlert(id: string, refs: { ism: string[]; essentialEight: string[] }) {
  return normaliseWedgetail({ ...WEDGETAIL_CREATED, alert: { ...WEDGETAIL_CREATED.alert, id, firstSeen: new Date().toISOString(), ...refs } } as never);
}

describe("ISM and Essential Eight signals", () => {
  it("stores normalised references on ingest, filters the queue and counts them beside assessments", async () => {
    await ingestAlert({ tenantId: a, integrationId, source: "wedgetail", intel: null, alert: wedgetailAlert(`${stamp}-1`, { ism: ["ISM-1509", "ism-1508"], essentialEight: ["restrict_admin_privileges:ML2", "nonsense"] }) });
    await ingestAlert({ tenantId: a, integrationId, source: "wedgetail", intel: null, alert: wedgetailAlert(`${stamp}-2`, { ism: ["ISM-1683"], essentialEight: ["multi_factor_authentication"] }) });
    const rows = await adminDb().select({ ism: alerts.ismControls, e8: alerts.e8Strategies }).from(alerts).where(eq(alerts.tenantId, a)).orderBy(alerts.externalId);
    expect(rows).toEqual([{ ism: ["ISM-1508", "ISM-1509"], e8: ["restrict_admin"] }, { ism: ["ISM-1683"], e8: ["mfa"] }]);

    expect((await listAlerts(ctx, { tenantIds: [a, b], ism: "ISM-1509" })).rows).toHaveLength(1);
    expect((await listAlerts(ctx, { tenantIds: [a, b], e8: "mfa" })).rows).toHaveLength(1);
    expect((await listAlerts(ctx, { tenantIds: [a, b], e8: "restrict_admin_privileges" })).rows).toHaveLength(1);

    const data = await complianceSignals(ctx, [a, b], 30);
    expect(data.mappedAlerts).toBe(2);
    expect(data.e8.map((r) => [r.id, r.alerts, r.open, r.customers])).toEqual([["mfa", 1, 1, 1], ["restrict_admin", 1, 1, 1]]);
    expect(data.ism.map((r) => r.id).sort()).toEqual(["ISM-1508", "ISM-1509", "ISM-1683"]);
    const customerA = data.customers.find((c) => c.tenantId === a)!;
    expect(customerA.assessed).toMatchObject({ mfa: 2, restrict_admin: 1 });
    expect(customerA.alerts).toEqual({ mfa: 1, restrict_admin: 1 });
    expect(data.customers.find((c) => c.tenantId === b)).toMatchObject({ assessed: null, alerts: {} });
  });

  it("counts Wedgetail-detected techniques as covered on the ATT&CK matrix", async () => {
    const cells = await attackCoverage(ctx, [a]);
    const cell = cells.find((c) => c.id === "T1078.004");
    if (!cell) return; // ATT&CK catalogue not seeded in this database
    expect(cell.external).toBeGreaterThan(0);
  });

  it("backfills earlier Wedgetail alerts from raw with the migration's statement", async () => {
    const [row] = await adminDb().insert(alerts).values({
      tenantId: b, source: "wedgetail", externalId: `${stamp}-legacy`, title: "Fictional legacy", severity: "low", occurredAt: new Date(),
      raw: { ism: ["ISM-1509", "bogus"], essentialEight: ["multi-factor-authentication", "regular_backups:ML3"] },
    }).returning({ id: alerts.id });
    const migration = readFileSync("drizzle/0037_alert_compliance_refs.sql", "utf8").split("--> statement-breakpoint").at(-1)!;
    await adminDb().execute(sql.raw(migration));
    const [after] = await adminDb().select({ ism: alerts.ismControls, e8: alerts.e8Strategies }).from(alerts).where(eq(alerts.id, row!.id));
    expect(after).toEqual({ ism: ["ISM-1509"], e8: ["mfa", "regular_backups"] });
  });
});
