/**
 * Correlation engine end to end: stored alerts → findings raised through ingest, deduped across runs,
 * kept inside their tenant; then automatic grouping into an incident and an analyst undoing it.
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import {
  alerts, auditLog, correlationCursors, correlationFindings, incidentAlerts, incidentGroupExclusions, incidentLinks, incidents, incidentTimeline, tenants, user,
} from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import type { AccessContext } from "@/lib/auth/access";
import { BUILTIN_ROLES, type Permission } from "@/lib/auth/permissions";
import { CORRELATION_SOURCE } from "@/lib/correlation/events";
import { ingestAlert } from "@/lib/pipeline/ingest";
import type { NormalisedAlert } from "@/lib/providers/types";
import { redis } from "@/lib/redis";
import { GROUP_BATCH, runCorrelation, runGrouping, setCorrelationRuleEnabled } from "@/lib/services/correlation";
import { ungroupAlerts } from "@/lib/services/incidents";

const run = randomUUID().slice(0, 8);
const now = new Date();
const HOUR = 3_600_000;
let tenantA = "";
let tenantB = "";
const ids: Record<string, string> = {};

const all = new Set(BUILTIN_ROLES.find((r) => r.key === "platform_admin")!.permissions as Permission[]);
const analyst = (): AccessContext => ({
  principal: { userId: `corr-analyst-${run}`, name: "Analyst", email: "a@example.invalid", isBreakGlass: false },
  isPlatform: true,
  grants: [{ roleKey: "platform_admin", tenantId: null, permissions: all }],
  tenantIds: [tenantA, tenantB],
  tenants: [
    { id: tenantA, slug: `corr-a-${run}`, name: "Correlation A", kind: "customer" },
    { id: tenantB, slug: `corr-b-${run}`, name: "Correlation B", kind: "customer" },
  ],
});

function m365(key: string, hoursAgo: number, eventType: string, title: string, techniques: string[]): NormalisedAlert {
  return {
    externalId: `${key}:${run}`, ruleId: eventType, title, description: null, category: "bec", siemSeverity: 12, severity: "high",
    occurredAt: new Date(now.getTime() - hoursAgo * HOUR), assetExternalId: null, hostname: null, userName: "alice@wattle.example",
    attackTechniques: techniques, routingKeys: [], raw: { eventType },
  };
}

async function seed(tenantId: string, prefix: string, withGrant: boolean) {
  const list = [
    m365("mfa", 3, "mfa_fatigue", "MFA fatigue (denied prompts, then approval)", ["T1621"]),
    m365("travel", 3, "impossible_travel", "Impossible travel followed by mailbox activity", ["T1078", "T1114.003"]),
    ...(withGrant ? [m365("oauth", 1, "oauth_consent", "Suspicious OAuth consent for mail", ["T1528"])] : []),
  ];
  for (const a of list) {
    const res = await ingestAlert({ tenantId, integrationId: null, source: "entra", alert: a, intel: null });
    ids[`${prefix}:${a.externalId.split(":")[0]}`] = res.alertId;
  }
}

const findingsOf = (tenantId: string) => adminDb().select().from(correlationFindings).where(eq(correlationFindings.tenantId, tenantId));

beforeAll(async () => {
  await adminDb().insert(user).values({ id: `corr-analyst-${run}`, name: "Analyst", email: `corr-${run}@example.invalid`, emailVerified: true });
  const [a] = await adminDb().insert(tenants).values({ name: "Correlation A", slug: `corr-a-${run}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  const [b] = await adminDb().insert(tenants).values({ name: "Correlation B", slug: `corr-b-${run}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  tenantA = a!.id;
  tenantB = b!.id;
  await seed(tenantA, "a", true);
  // Same user name, same first two steps, no persistence step: must not borrow tenant A's OAuth grant.
  await seed(tenantB, "b", false);
});

afterAll(async () => {
  for (const id of [tenantA, tenantB].filter(Boolean)) await adminDb().delete(tenants).where(eq(tenants.id, id));
  await adminDb().delete(user).where(eq(user.id, `corr-analyst-${run}`));
  await redis().quit();
});

describe("correlation engine", () => {
  it("raises the account takeover chain through ingest with every contributing alert, inside its tenant", async () => {
    const a = await runCorrelation(tenantA, now);
    const b = await runCorrelation(tenantB, now);
    expect(a.created).toBeGreaterThanOrEqual(1);

    const [ato, ...more] = (await findingsOf(tenantA)).filter((f) => f.ruleId === "account-takeover");
    expect(more).toEqual([]);
    expect(ato!.ruleVersion).toBe(1);
    expect(ato!.entity).toEqual({ user: "alice@wattle.example" });
    expect(ato!.matches.map((m) => [m.clause, m.events.map((e) => e.id)])).toEqual([
      ["ato.pressure", [ids["a:mfa"]]],
      ["ato.access", [ids["a:travel"]]],
      ["ato.persistence", [ids["a:oauth"]]],
    ]);
    expect(ato!.explanation.join("\n")).toContain(`[${ids["a:oauth"]}]`);

    const [alert] = await adminDb().select().from(alerts).where(eq(alerts.id, ato!.alertId!));
    expect(alert).toMatchObject({ tenantId: tenantA, source: CORRELATION_SOURCE, externalId: ato!.dedupeKey, ruleId: "account-takeover", severity: "critical", userName: "alice@wattle.example" });
    expect(alert!.riskFactors.length).toBeGreaterThan(0);
    expect(alert!.ocsf).toMatchObject({ class_uid: 2004, metadata: { log_name: CORRELATION_SOURCE, tenant_uid: tenantA, product: { name: "blakSOC correlation engine" } } });

    const [entry] = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenantA), eq(auditLog.action, "correlation.finding"), eq(auditLog.targetId, alert!.id)));
    expect(entry).toBeTruthy();

    // Tenant B saw the same user name but never tenant A's events.
    expect(b.created).toBe(0);
    const bIds = new Set(Object.entries(ids).filter(([k]) => k.startsWith("b:")).map(([, v]) => v));
    for (const f of await findingsOf(tenantA)) for (const m of f.matches) for (const e of m.events) expect(bIds.has(e.id)).toBe(false);
    expect((await findingsOf(tenantB)).filter((f) => f.ruleId === "account-takeover")).toEqual([]);
  });

  it("keeps findings behind RLS", async () => {
    const asB = await withScope({ tenantIds: [tenantB], grantIds: [tenantB], platform: false }, (tx) => tx.select().from(correlationFindings).where(eq(correlationFindings.tenantId, tenantA)));
    expect(asB).toEqual([]);
    const asA = await withScope({ tenantIds: [tenantA], grantIds: [tenantA], platform: false }, (tx) => tx.select().from(correlationFindings));
    expect(asA.length).toBeGreaterThan(0);
    expect(asA.every((f) => f.tenantId === tenantA)).toBe(true);
  });

  it("never raises the same finding twice, even with the cursor reset", async () => {
    const before = await findingsOf(tenantA);
    const again = await runCorrelation(tenantA, now);
    expect(again.created).toBe(0);
    await adminDb().delete(correlationCursors).where(eq(correlationCursors.tenantId, tenantA));
    const reset = await runCorrelation(tenantA, new Date(now.getTime() + 60_000));
    expect(reset.created).toBe(0);
    expect((await findingsOf(tenantA)).length).toBe(before.length);
    const raised = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenantA), eq(alerts.source, CORRELATION_SOURCE)));
    expect(raised.length).toBe(before.length);
  });

  it("honours a tenant switching a rule off", async () => {
    await setCorrelationRuleEnabled(analyst(), tenantB, "account-takeover", false);
    const res = await ingestAlert({ tenantId: tenantB, integrationId: null, source: "entra", alert: m365("oauth", 1, "oauth_consent", "Suspicious OAuth consent for mail", ["T1528"]), intel: null });
    ids["b:oauth"] = res.alertId;
    await runCorrelation(tenantB, now);
    expect((await findingsOf(tenantB)).filter((f) => f.ruleId === "account-takeover")).toEqual([]);
  });
});

describe("automatic incident grouping", () => {
  let incidentId = "";
  let members: string[] = [];

  it("groups the chain and its correlated alert into one incident, recording why", async () => {
    const res = await runGrouping(tenantA, now);
    expect(res.opened).toBe(1);
    const [ato] = (await findingsOf(tenantA)).filter((f) => f.ruleId === "account-takeover");
    members = [ids["a:mfa"]!, ids["a:travel"]!, ids["a:oauth"]!, ato!.alertId!];

    const links = await adminDb().select().from(incidentAlerts).where(inArray(incidentAlerts.alertId, members));
    expect(links).toHaveLength(4);
    incidentId = links[0]!.incidentId;
    expect(links.every((l) => l.incidentId === incidentId && l.origin === "auto" && l.priorStatus === "NEW")).toBe(true);
    expect(links[0]!.reason).toMatchObject({ entities: ["user:alice@wattle.example"], windowMs: 6 * HOUR });

    const [inc] = await adminDb().select().from(incidents).where(eq(incidents.id, incidentId));
    expect(inc!.groupingKey).toMatch(/^grp:/);
    expect(inc!.description).toContain("Grouped automatically: same user:alice@wattle.example");
    const timeline = await adminDb().select().from(incidentTimeline).where(and(eq(incidentTimeline.incidentId, incidentId), eq(incidentTimeline.category, "grouping")));
    expect(timeline.map((t) => t.title)).toEqual(["Opened by automatic grouping of 4 alerts"]);
    const statuses = await adminDb().select({ status: alerts.status, incidentId: alerts.incidentId }).from(alerts).where(inArray(alerts.id, members));
    expect(statuses.every((s) => s.status === "ESCALATED" && s.incidentId === incidentId)).toBe(true);

    // Tenant B's alerts (rule off, no correlated alert) group on their own, never with tenant A's.
    const bLinks = await adminDb().select().from(incidentAlerts).where(eq(incidentAlerts.tenantId, tenantB));
    expect(bLinks.every((l) => l.incidentId !== incidentId)).toBe(true);
  });

  it("is idempotent: grouping again changes nothing", async () => {
    const again = await runGrouping(tenantA, now);
    expect(again).toEqual({ plans: 0, linked: 0, opened: 0 });
    expect(await adminDb().select().from(incidents).where(eq(incidents.tenantId, tenantA))).toHaveLength(1);
  });

  it("lets an analyst ungroup one alert, then the rest, restoring each alert and closing the empty incident", async () => {
    const oauth = ids["a:oauth"]!;
    const first = await ungroupAlerts(analyst(), incidentId, [oauth]);
    expect(first).toEqual({ alertIds: [oauth], closed: false });
    const [one] = await adminDb().select().from(alerts).where(eq(alerts.id, oauth));
    expect(one).toMatchObject({ status: "NEW", incidentId: null });

    const rest = await ungroupAlerts(analyst(), incidentId);
    expect(rest.closed).toBe(true);
    expect(await adminDb().select().from(incidentAlerts).where(eq(incidentAlerts.incidentId, incidentId))).toEqual([]);
    const restored = await adminDb().select({ status: alerts.status, incidentId: alerts.incidentId }).from(alerts).where(inArray(alerts.id, members));
    expect(restored.every((s) => s.status === "NEW" && s.incidentId === null)).toBe(true);
    expect(await adminDb().select().from(incidentLinks).where(and(eq(incidentLinks.incidentId, incidentId), eq(incidentLinks.kind, "identity")))).toEqual([]);

    const [inc] = await adminDb().select().from(incidents).where(eq(incidents.id, incidentId));
    expect(inc!.status).toBe("CLOSED");
    const timeline = await adminDb().select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, incidentId));
    expect(timeline.filter((t) => t.category === "grouping").map((t) => t.title)).toEqual(["Opened by automatic grouping of 4 alerts", "Ungrouped 1 alert", "Ungrouped 3 alerts"]);
    expect(timeline.some((t) => t.title === "Status OPEN → CLOSED")).toBe(true);
    const audits = await adminDb().select().from(auditLog).where(and(eq(auditLog.action, "incident.ungroup"), eq(auditLog.targetId, incidentId)));
    expect(audits).toHaveLength(2);

    // The analyst's decision sticks: grouping leaves these alerts alone from now on.
    expect(await adminDb().select().from(incidentGroupExclusions).where(inArray(incidentGroupExclusions.alertId, members))).toHaveLength(4);
    expect(await runGrouping(tenantA, now)).toEqual({ plans: 0, linked: 0, opened: 0 });
  });

  it("refuses to ungroup alerts an analyst linked by hand", async () => {
    const [inc] = await adminDb().insert(incidents).values({ tenantId: tenantA, title: "Manual case", severity: "high" }).returning();
    await adminDb().insert(incidentAlerts).values({ tenantId: tenantA, incidentId: inc!.id, alertId: ids["a:mfa"]! });
    await expect(ungroupAlerts(analyst(), inc!.id)).rejects.toThrow(/only automatically grouped alerts/);
  });
});

describe("grouping a large burst", () => {
  let tenantC = "";
  beforeAll(async () => {
    const [c] = await adminDb().insert(tenants).values({ name: "Correlation C", slug: `corr-c-${run}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
    tenantC = c!.id;
  });
  afterAll(async () => {
    if (tenantC) await adminDb().delete(tenants).where(eq(tenants.id, tenantC));
  });

  it("links a group bigger than one batch into a single incident, one short transaction per batch", async () => {
    const n = GROUP_BATCH * 2 + 30;
    for (let i = 0; i < n; i++) {
      const a = m365(`burst${i}`, 2, "mailbox_rule", `Mailbox rule ${i}`, ["T1114.003"]);
      await ingestAlert({ tenantId: tenantC, integrationId: null, source: "entra", alert: { ...a, occurredAt: new Date(a.occurredAt.getTime() + i * 1000) }, intel: null });
    }
    const res = await runGrouping(tenantC, now);
    expect(res).toMatchObject({ opened: 1, linked: n });
    const incs = await adminDb().select().from(incidents).where(eq(incidents.tenantId, tenantC));
    expect(incs).toHaveLength(1);
    expect(await adminDb().select().from(incidentAlerts).where(eq(incidentAlerts.incidentId, incs[0]!.id))).toHaveLength(n);
    const titles = (await adminDb().select().from(incidentTimeline).where(and(eq(incidentTimeline.incidentId, incs[0]!.id), eq(incidentTimeline.category, "grouping")))).map((t) => t.title);
    expect(titles.sort()).toEqual([`Grouped ${GROUP_BATCH} related alerts automatically`, `Grouped 30 related alerts automatically`, `Opened by automatic grouping of ${GROUP_BATCH} alerts`].sort());
    expect(await runGrouping(tenantC, now)).toEqual({ plans: 0, linked: 0, opened: 0 });
  }, 120_000);
});

describe("which alerts open incidents", () => {
  let tenantD = "";
  beforeAll(async () => {
    const [d] = await adminDb().insert(tenants).values({ name: "Correlation D", slug: `corr-d-${run}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
    tenantD = d!.id;
  });
  afterAll(async () => {
    if (tenantD) await adminDb().delete(tenants).where(eq(tenants.id, tenantD));
  });

  it("opens an incident for one high alert and leaves medium alerts in the queue", async () => {
    const high = m365("solo-high", 1, "mailbox_rule", "Suspicious mailbox rule", ["T1114.003"]);
    const medium = { ...m365("solo-medium", 1, "mailbox_rule", "Benchmark check failed", ["T1114.003"]), severity: "medium" as const };
    const h = await ingestAlert({ tenantId: tenantD, integrationId: null, source: "entra", alert: high, intel: null });
    const m = await ingestAlert({ tenantId: tenantD, integrationId: null, source: "entra", alert: medium, intel: null });
    expect(await runGrouping(tenantD, now)).toMatchObject({ opened: 1, linked: 1 });
    const rows = await adminDb().select({ id: alerts.id, incidentId: alerts.incidentId }).from(alerts).where(inArray(alerts.id, [h.alertId, m.alertId]));
    expect(rows.find((r) => r.id === h.alertId)!.incidentId).toBeTruthy();
    expect(rows.find((r) => r.id === m.alertId)!.incidentId).toBeNull();
  });

  it("raises the incident's severity when a more severe related alert joins it", async () => {
    const critical = { ...m365("solo-critical", 0.5, "mailbox_rule", "Mailbox forwarding to external domain", ["T1114.003"]), severity: "critical" as const };
    const c = await ingestAlert({ tenantId: tenantD, integrationId: null, source: "entra", alert: critical, intel: null });
    await runGrouping(tenantD, now);
    const [row] = await adminDb().select({ incidentId: alerts.incidentId }).from(alerts).where(eq(alerts.id, c.alertId));
    const [inc] = await adminDb().select().from(incidents).where(eq(incidents.id, row!.incidentId!));
    expect(inc!.severity).toBe("critical");
    const timeline = await adminDb().select({ title: incidentTimeline.title }).from(incidentTimeline).where(eq(incidentTimeline.incidentId, inc!.id));
    expect(timeline.map((t) => t.title)).toContain("Severity raised high → critical by a grouped alert");
  });
});
