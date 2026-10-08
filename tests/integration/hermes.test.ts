/**
 * The tuning API for Hermes, end to end through the route handlers: scopes, what it may see (aggregates only),
 * what it may do (guardrails, the act switch, caps), undo, purge after the undo window, reports and memory.
 */
import { randomUUID } from "node:crypto";
import { and, eq, inArray, isNotNull, isNull } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { GET as listActionsRoute } from "@/app/api/v1/tuning/actions/route";
import { GET as getMemoryRoute, PUT as putMemoryRoute } from "@/app/api/v1/tuning/memory/route";
import { POST as createNoiseRuleRoute } from "@/app/api/v1/tuning/noise-rules/route";
import { POST as annotateRoute } from "@/app/api/v1/tuning/patterns/[patternId]/annotations/route";
import { POST as closeRoute } from "@/app/api/v1/tuning/patterns/[patternId]/close/route";
import { POST as purgeRoute } from "@/app/api/v1/tuning/patterns/[patternId]/purge/route";
import { GET as listPatternsRoute } from "@/app/api/v1/tuning/patterns/route";
import { GET as listReportsRoute, POST as createReportRoute } from "@/app/api/v1/tuning/reports/route";
import { POST as tokenRoute } from "@/app/api/v1/oauth/token/route";
import { adminDb } from "@/db/client";
import { alerts, auditLog, hermesMemoryNotes, hermesReports, incidents, noiseRules, platformSettings, serviceIdentities, tenants, tuningActions, user } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { redis } from "@/lib/redis";
import { addHumanNote, getMemory, listReports, MEMORY_VERSION_KEY, MEMORY_RETENTION_KEY, runHermesRetention, setHermesRetention } from "@/lib/services/hermes";
import { createServiceIdentity } from "@/lib/services/service-identities";
import { listAlerts } from "@/lib/services/alerts";
import {
  annotationsForAlert, closingAction, dispositionStats, HERMES_ACT_KEY, hermesRecentActionCount, hermesSwitchState, hermesWeek, listTuningActions, recentAnnotations, setHermesMayAct, tuningActionSummary, undoTuningAction,
} from "@/lib/services/tuning";
import { hermesClosure } from "@/lib/tuning/hermes-ui";

const BASE = "http://localhost/api/v1/tuning";
const run = randomUUID().slice(0, 8);
const DAY = 86_400_000;
const now = new Date();
const SECRET_HOST = `secret-host-${run}.corp.local`;
const SECRET_USER = `jane.doe.${run}`;
const TENANT_NAME = `Hermes Tenant ${run}`;

let tenant = "";
let admin: AccessContext;
const identities: string[] = [];
const tokens: Record<string, string> = {};
const patterns: Record<string, string> = {};
/** The first closure (4 alerts), which an analyst undoes. */
let firstCloseAction = "";

async function token(clientId: string, clientSecret: string) {
  const res = await tokenRoute(new Request("http://localhost/api/v1/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}` },
    body: "grant_type=client_credentials",
  }));
  return ((await res.json()) as { access_token: string }).access_token;
}

const call = (t: string, init: RequestInit = {}) => ({ ...init, headers: { "content-type": "application/json", ...(init.headers ?? {}), authorization: `Bearer ${t}` } });
const post = (t: string, body: unknown) => call(t, { method: "POST", body: JSON.stringify(body) });
const pid = (patternId: string) => ({ params: Promise.resolve({ patternId }) });
const body = async (res: Response) => (await res.json()) as Record<string, unknown> & { error?: string; message?: string };

let n = 0;
async function seed(ruleId: string, rows: { status?: (typeof alerts.$inferInsert)["status"]; severity?: (typeof alerts.$inferInsert)["severity"]; daysAgo?: number; incidentId?: string; count?: number }[]) {
  for (const r of rows) {
    for (let i = 0; i < (r.count ?? 1); i++) {
      n++;
      await adminDb().insert(alerts).values({
        tenantId: tenant, source: "wazuh", externalId: `hermes-${run}-${n}`, ruleId,
        title: `Login failure for ${SECRET_USER} on ${SECRET_HOST}`, description: `${SECRET_USER} from 10.9.8.7`,
        severity: r.severity ?? "low", status: r.status ?? "NEW", userName: SECRET_USER, incidentId: r.incidentId ?? null,
        occurredAt: new Date(now.getTime() - (r.daysAgo ?? 1) * DAY - n * 1000),
        raw: { rule: { id: ruleId, level: 5, description: `Login failure for ${SECRET_USER}`, groups: ["sshd", SECRET_HOST], mitre: { id: ["T1110"] } }, decoder: { name: "sshd" }, agent: { name: SECRET_HOST, ip: "10.9.8.7" }, full_log: SECRET_USER },
      });
    }
  }
}

beforeAll(async () => {
  const [t] = await adminDb().insert(tenants).values({ name: TENANT_NAME, slug: `hermes-${run}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  tenant = t!.id;
  const [u] = await adminDb().select().from(user).where(eq(user.email, "breakglass@blaksoc.local"));
  admin = await resolveAccess({ userId: u!.id, name: u!.name, email: u!.email, isBreakGlass: u!.isBreakGlass });

  const make = async (name: string, tenantId: string | null, scopes: string[]) => {
    const id = await createServiceIdentity(admin, { name: `${name} ${run}`, tenantId, scopes });
    identities.push(id.id);
    tokens[name] = await token(id.id, id.clientSecret);
  };
  await make("hermes", null, ["tuning:read", "tuning:annotate", "tuning:act", "tuning:report", "tuning:memory"]);
  await make("reader", null, ["tuning:read"]);
  await make("alerts", null, ["alert:read"]);
  await make("tenantBound", tenant, ["tuning:read", "tuning:report"]);

  const [inc] = await adminDb().insert(incidents).values({ tenantId: tenant, title: "linked", severity: "low" }).returning();
  // A pattern analysts keep closing as false positive: 12 closed (all FP), then open alerts of mixed stakes.
  await seed("hermes-fp", [
    { status: "FALSE_POSITIVE", daysAgo: 40, count: 12 },
    { status: "NEW", severity: "low", count: 3 },
    { status: "TRIAGING", severity: "medium", count: 1 },
    { status: "INVESTIGATING", severity: "low", count: 1 },
    { status: "NEW", severity: "high", count: 1 },
    { status: "NEW", severity: "critical", count: 1 },
    // On an incident, but long enough ago that the pattern is quiet: never closed by the agent.
    { status: "NEW", severity: "low", incidentId: inc!.id, daysAgo: 45, count: 1 },
  ]);
  await seed("hermes-few", [{ status: "FALSE_POSITIVE", count: 4 }, { status: "NEW" }]);
  await seed("hermes-esc", [{ status: "FALSE_POSITIVE", daysAgo: 50, count: 12 }, { status: "ESCALATED", daysAgo: 5 }, { status: "NEW" }]);
  await adminDb().delete(platformSettings).where(eq(platformSettings.key, HERMES_ACT_KEY));

  const res = await listPatternsRoute(new Request(`${BASE}/patterns?days=90`, call(tokens.hermes!)));
  const list = (await res.json()) as { patterns: { patternId: string; ruleId: string }[] };
  for (const p of list.patterns) if (p.ruleId.startsWith("hermes-")) patterns[p.ruleId] = p.patternId;
});

afterAll(async () => {
  if (identities.length) await adminDb().delete(serviceIdentities).where(inArray(serviceIdentities.id, identities));
  if (identities.length) await adminDb().delete(hermesReports).where(inArray(hermesReports.createdBy, identities));
  await adminDb().delete(hermesMemoryNotes).where(inArray(hermesMemoryNotes.createdBy, [...identities, admin.principal.userId]));
  await adminDb().delete(platformSettings).where(inArray(platformSettings.key, [HERMES_ACT_KEY, MEMORY_VERSION_KEY, MEMORY_RETENTION_KEY]));
  if (tenant) await adminDb().delete(tenants).where(eq(tenants.id, tenant));
  await redis().quit();
});

describe("scopes", () => {
  it("refuses tokens without the tuning scope each endpoint needs", async () => {
    expect((await listPatternsRoute(new Request(`${BASE}/patterns`, call(tokens.alerts!)))).status).toBe(403);
    expect((await closeRoute(new Request(`${BASE}/patterns/x/close`, post(tokens.reader!, { reason: "x" })), pid(patterns["hermes-fp"]!))).status).toBe(403);
    expect((await createNoiseRuleRoute(new Request(`${BASE}/noise-rules`, post(tokens.reader!, { patternId: patterns["hermes-fp"], reason: "x" })))).status).toBe(403);
    expect((await purgeRoute(new Request(`${BASE}/patterns/x/purge`, call(tokens.reader!, { method: "POST" })), pid(patterns["hermes-fp"]!))).status).toBe(403);
    expect((await annotateRoute(new Request(`${BASE}/patterns/x/annotations`, post(tokens.reader!, { text: "x", confidence: "low" })), pid(patterns["hermes-fp"]!))).status).toBe(403);
    expect((await putMemoryRoute(new Request(`${BASE}/memory`, call(tokens.reader!, { method: "PUT", body: JSON.stringify({ version: 0, notes: [] }) })))).status).toBe(403);
    expect((await createReportRoute(new Request(`${BASE}/reports`, post(tokens.reader!, {})))).status).toBe(403);
    // Reports and memory are platform data: a tenant-bound identity is refused even with the scope.
    expect((await listReportsRoute(new Request(`${BASE}/reports`, call(tokens.tenantBound!)))).status).toBe(403);
    expect((await getMemoryRoute(new Request(`${BASE}/memory`, call(tokens.tenantBound!)))).status).toBe(403);
    expect((await listPatternsRoute(new Request(`${BASE}/patterns`, { headers: {} }))).status).toBe(401);
  });

  it("answers 404 for a pattern id it never handed out", async () => {
    const res = await closeRoute(new Request(`${BASE}/patterns/x/close`, post(tokens.hermes!, { reason: "x" })), pid("P-AAAAAAAAAAAAAAAAAAAAAA"));
    expect(res.status).toBe(404);
  });
});

describe("patterns", () => {
  it("returns aggregates and opaque ids only: no titles, hosts, users, addresses or tenant names", async () => {
    const res = await listPatternsRoute(new Request(`${BASE}/patterns?days=90`, call(tokens.hermes!)));
    expect(res.status).toBe(200);
    const text = await res.text();
    for (const secret of [SECRET_HOST, SECRET_USER, "jane.doe", "corp.local", "10.9.8.7", TENANT_NAME, tenant, "Login failure"]) expect(text, secret).not.toContain(secret);
    type Pattern = {
      patternId: string; tenantRef: string; ruleId: string; ruleLevel: number; ruleGroups: string[]; mitre: string[]; distinctUsers: number; severity: Record<string, number>;
      counts: { total: number; byDay: number[]; byHourOfDay: number[] }; dispositions: Record<"d30" | "d90", { falsePositive: number }>;
    };
    const doc = JSON.parse(text) as { patterns: Pattern[]; fleet: unknown[] };
    const p = doc.patterns.find((x) => x.ruleId === "hermes-fp")!;
    expect(p.patternId).toBe(patterns["hermes-fp"]);
    expect(p.tenantRef).toMatch(/^T-[0-9a-f]{6}$/);
    expect(p).toMatchObject({ ruleLevel: 5, ruleGroups: ["sshd"], mitre: ["T1110"] });
    expect(p.patternId).toMatch(/^[A-Za-z0-9_-]{1,100}$/);
    expect(p.counts.byDay).toHaveLength(91);
    expect(p.counts.byDay.reduce((a, b) => a + b, 0)).toBe(p.counts.total);
    expect(p.counts.total).toBe(20);
    expect(p.counts.byHourOfDay).toHaveLength(24);
    expect(p.distinctUsers).toBe(1);
    expect(p.dispositions.d90.falsePositive).toBe(12);
    expect(p.dispositions.d30.falsePositive).toBe(0);
    expect(p.severity).toMatchObject({ high: 1, critical: 1 });
    expect(doc.fleet.length).toBeGreaterThan(0);
    expect((await listPatternsRoute(new Request(`${BASE}/patterns?days=91`, call(tokens.hermes!)))).status).toBe(400);
  });

  it("stores annotations as AI notes and returns them with the pattern", async () => {
    const res = await annotateRoute(new Request(`${BASE}/patterns/x/annotations`, post(tokens.hermes!, { text: "Nightly scanner\u0007 pattern; benign.", confidence: "medium" })), pid(patterns["hermes-fp"]!));
    expect(res.status).toBe(201);
    const list = (await (await listPatternsRoute(new Request(`${BASE}/patterns?days=90`, call(tokens.hermes!)))).json()) as { patterns: { ruleId: string; annotations: { text: string }[] }[] };
    expect(list.patterns.find((p) => p.ruleId === "hermes-fp")!.annotations[0]).toMatchObject({ text: "Nightly scanner pattern; benign.", authorKind: "service", confidence: "medium" });
    const [entry] = await adminDb().select().from(auditLog).where(and(eq(auditLog.action, "tuning.annotate"), eq(auditLog.actorId, identities[0]!)));
    expect(entry?.actorKind).toBe("service");
  });
});

describe("acting", () => {
  it("is refused with 409 while “Allow Hermes to act” is off", async () => {
    const res = await closeRoute(new Request(`${BASE}/patterns/x/close`, post(tokens.hermes!, { reason: "noise" })), pid(patterns["hermes-fp"]!));
    expect(res.status).toBe(409);
    expect((await body(res)).error).toBe("hermes_actions_disabled");
    await setHermesMayAct(admin, true);
  });

  it("refuses patterns with too few human closures or a recent escalation", async () => {
    const few = await closeRoute(new Request(`${BASE}/patterns/x/close`, post(tokens.hermes!, { reason: "noise" })), pid(patterns["hermes-few"]!));
    expect(few.status).toBe(422);
    expect((await body(few)).message).toMatch(/at least 10/);
    const esc = await closeRoute(new Request(`${BASE}/patterns/x/close`, post(tokens.hermes!, { reason: "noise" })), pid(patterns["hermes-esc"]!));
    expect(esc.status).toBe(422);
    expect((await body(esc)).message).toMatch(/escalated/);
  });

  let closeAction = "";
  it("closes only open, low-stakes alerts that are not on an incident; analysts can undo it", async () => {
    const res = await closeRoute(new Request(`${BASE}/patterns/x/close`, post(tokens.hermes!, { reason: "Benign scanner noise" })), pid(patterns["hermes-fp"]!));
    expect(res.status).toBe(200);
    const out = await body(res);
    expect(out.affected).toBe(4); // 3 NEW low + 1 TRIAGING medium
    closeAction = out.actionId as string;
    firstCloseAction = closeAction;
    const rows = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant), eq(alerts.ruleId, "hermes-fp")));
    const closed = rows.filter((r) => r.tuningActionId === closeAction);
    expect(closed).toHaveLength(4);
    expect(closed.every((r) => r.status === "FALSE_POSITIVE" && ["low", "medium"].includes(r.severity) && !r.incidentId)).toBe(true);
    expect(rows.filter((r) => ["high", "critical"].includes(r.severity)).every((r) => r.status === "NEW")).toBe(true);
    expect(rows.find((r) => r.incidentId)!.status).toBe("NEW");
    expect(rows.find((r) => r.status === "INVESTIGATING")).toBeDefined();

    // Hermes' closures are not analyst decisions: neither its next evidence nor ingest scoring may count them.
    const listed = (await (await listPatternsRoute(new Request(`${BASE}/patterns?days=90`, call(tokens.hermes!)))).json()) as { patterns: { patternId: string; dispositions: Record<"d30" | "d90", { falsePositive: number }> }[] };
    expect(listed.patterns.find((p) => p.patternId === patterns["hermes-fp"])!.dispositions.d90.falsePositive).toBe(12);
    const stats = await withScope(systemScope(tenant), (tx) => dispositionStats(tx, { tenantId: tenant, source: "wazuh", ruleId: "hermes-fp", assetId: null }));
    expect(stats.rule.falsePositive).toBe(12);

    const undone = await undoTuningAction(admin, closeAction);
    expect(undone.restored).toBe(4);
    const after = await adminDb().select().from(alerts).where(eq(alerts.tuningActionId, closeAction));
    expect(after.every((r) => r.status === "NEW")).toBe(true);
    await expect(undoTuningAction(admin, closeAction)).rejects.toThrow(/already undone/);

    const actions = (await (await listActionsRoute(new Request(`${BASE}/actions`, call(tokens.hermes!)))).json()) as { actions: { id: string; undoneAt: string | null; status: string; affected: number; reopenedCount: number }[] };
    const a = actions.actions.find((x) => x.id === closeAction)!;
    expect(a).toMatchObject({ status: "undone", affected: 4 });
    expect(a.undoneAt).not.toBeNull();
    expect(JSON.stringify(actions)).not.toContain(admin.principal.name);
  });

  it("purges nothing inside the 7-day undo window, then only untouched closures after it", async () => {
    const req = () => new Request(`${BASE}/patterns/x/close`, post(tokens.hermes!, { reason: "Benign scanner noise", maxAlerts: 2 }));
    const keyed = () => { const r = req(); r.headers.set("idempotency-key", `close-${run}`); return r; };
    const res = await closeRoute(keyed(), pid(patterns["hermes-fp"]!));
    const { actionId, affected } = await body(res);
    expect(affected).toBe(2);
    // A retry with the same Idempotency-Key replays the answer instead of closing two more.
    const again = await closeRoute(keyed(), pid(patterns["hermes-fp"]!));
    expect(again.headers.get("idempotent-replayed")).toBe("true");
    expect((await body(again)).actionId).toBe(actionId);
    expect(await adminDb().select().from(alerts).where(eq(alerts.tuningActionId, actionId as string))).toHaveLength(2);
    const early = await purgeRoute(new Request(`${BASE}/patterns/x/purge`, call(tokens.hermes!, { method: "POST" })), pid(patterns["hermes-fp"]!));
    expect(early.status).toBe(409);
    expect((await body(early)).error).toBe("undo_window");

    // Eight days later, one of the two was reopened and re-closed by an analyst: only the other may go.
    const past = new Date(now.getTime() - 8 * DAY);
    await adminDb().update(tuningActions).set({ createdAt: past, reversibleUntil: new Date(past.getTime() + 7 * DAY) }).where(eq(tuningActions.id, actionId as string));
    const ids = (await adminDb().select({ id: alerts.id }).from(alerts).where(eq(alerts.tuningActionId, actionId as string))).map((r) => r.id);
    await adminDb().update(alerts).set({ updatedAt: past }).where(eq(alerts.id, ids[0]!));
    await adminDb().update(alerts).set({ updatedAt: new Date() }).where(eq(alerts.id, ids[1]!));
    const purged = await purgeRoute(new Request(`${BASE}/patterns/x/purge`, call(tokens.hermes!, { method: "POST" })), pid(patterns["hermes-fp"]!));
    expect(purged.status).toBe(200);
    expect((await body(purged)).deleted).toBe(1);
    expect(await adminDb().select().from(alerts).where(eq(alerts.id, ids[0]!))).toEqual([]);
    expect(await adminDb().select().from(alerts).where(eq(alerts.id, ids[1]!))).toHaveLength(1);
  });

  it("creates whole-pattern noise rules capped at medium and 30 days, and undo restores the queue", async () => {
    const tooLong = await createNoiseRuleRoute(new Request(`${BASE}/noise-rules`, post(tokens.hermes!, { patternId: patterns["hermes-fp"], reason: "noise", expiresInDays: 31 })));
    expect(tooLong.status).toBe(400);
    const refused = await createNoiseRuleRoute(new Request(`${BASE}/noise-rules`, post(tokens.hermes!, { patternId: patterns["hermes-esc"], reason: "noise", expiresInDays: 7 })));
    expect(refused.status).toBe(422);
    const res = await createNoiseRuleRoute(new Request(`${BASE}/noise-rules`, post(tokens.hermes!, { patternId: patterns["hermes-fp"], reason: "Scanner noise", expiresInDays: 7 })));
    expect(res.status).toBe(201);
    const out = await body(res);
    const [r] = await adminDb().select().from(noiseRules).where(eq(noiseRules.id, out.noiseRuleId as string));
    expect(r).toMatchObject({ status: "active", createdByKind: "service", maxSeverity: "medium", assetId: null, hostname: null });
    const passive = await adminDb().select().from(alerts).where(eq(alerts.noiseRuleId, r!.id));
    expect(passive.length).toBe(out.movedToPassive);
    expect(passive.every((a) => a.lane === "passive" && ["informational", "low", "medium"].includes(a.severity))).toBe(true);
    const dupe = await createNoiseRuleRoute(new Request(`${BASE}/noise-rules`, post(tokens.hermes!, { patternId: patterns["hermes-fp"], reason: "again", expiresInDays: 7 })));
    expect(dupe.status).toBe(409);

    const undone = await undoTuningAction(admin, out.actionId as string);
    expect(undone.restored).toBe(passive.length);
    const [expired] = await adminDb().select().from(noiseRules).where(eq(noiseRules.id, r!.id));
    expect(expired!.status).toBe("expired");
    expect((await adminDb().select().from(alerts).where(eq(alerts.noiseRuleId, r!.id))).length).toBe(0);
  });
});

describe("reports and memory", () => {
  const stats = { executed: 3, refused: 1, dryRun: 0, patternsReviewed: 40 };
  const report = (markdown: string) => ({ periodStart: new Date(now.getTime() - DAY).toISOString(), periodEnd: now.toISOString(), markdown, stats });

  it("stores plain-markdown reports up to 50 KB and lists them", async () => {
    expect((await createReportRoute(new Request(`${BASE}/reports`, post(tokens.hermes!, report("# Run\n\n- closed 3 patterns"))))).status).toBe(201);
    expect((await createReportRoute(new Request(`${BASE}/reports`, post(tokens.hermes!, report("x".repeat(50 * 1024 + 1)))))).status).toBe(413);
    expect((await createReportRoute(new Request(`${BASE}/reports`, post(tokens.hermes!, report("<script>alert(1)</script>"))))).status).toBe(422);
    const list = (await (await listReportsRoute(new Request(`${BASE}/reports?limit=5`, call(tokens.hermes!)))).json()) as { reports: { markdown: string; stats: unknown }[] };
    expect(list.reports[0]).toMatchObject({ markdown: "# Run\n\n- closed 3 patterns", stats });
  });

  it("replaces memory with optimistic concurrency, refuses identifiers, and keeps analysts' notes", async () => {
    type Memory = { version: number; notes: { id: string; kind: string; text: string }[] };
    const read = async () => (await (await getMemoryRoute(new Request(`${BASE}/memory`, call(tokens.hermes!)))).json()) as Memory;
    const put = (version: number, notes: unknown[], headers: Record<string, string> = {}) =>
      putMemoryRoute(new Request(`${BASE}/memory`, call(tokens.hermes!, { method: "PUT", body: JSON.stringify({ version, notes }), headers })));
    const first = await read();
    const ok = await put(first.version, [{ kind: "model", text: "Rule 5710 is scanner noise at 02:00" }, { kind: "outcome", text: "Closures on 5710 were never reopened" }]);
    expect(ok.status).toBe(200);
    expect(await body(ok)).toMatchObject({ version: first.version + 1, added: 2, removed: 0 });

    const stale = await put(first.version, []);
    expect(stale.status).toBe(409);
    expect(await body(stale)).toMatchObject({ error: "version_conflict", currentVersion: first.version + 1 });

    for (const text of ["Host dc01.corp.local is noisy", "From 10.1.2.3", "Ask bob@example.com"]) {
      const res = await put(first.version + 1, [{ kind: "model", text }]);
      expect(res.status, text).toBe(422);
    }

    await addHumanNote(admin, { text: "Never close rule 100210 automatically" });
    const mem = await read();
    expect(mem.version).toBe(first.version + 2);
    const model = mem.notes.find((x) => x.kind === "model")!;
    const human = mem.notes.find((x) => x.kind === "human")!;
    // Keep the model note (by id), drop the outcome note, try to rewrite the analyst's note: it is kept as it was.
    const replaced = await put(mem.version, [{ id: model.id, kind: "model", text: model.text }, { id: human.id, kind: "human", text: "rewritten" }]);
    expect(await body(replaced)).toMatchObject({ removed: 1, unchanged: 1, added: 0 });
    const after = await read();
    expect(after.notes.map((x) => x.kind).sort()).toEqual(["human", "model"]);
    expect(after.notes.find((x) => x.kind === "human")!.text).toBe("Never close rule 100210 automatically");
    // Even a legacy client that omits IDs must not reset an unchanged note's age every hour.
    const [beforeSave] = await adminDb().select().from(hermesMemoryNotes).where(eq(hermesMemoryNotes.id, model.id));
    expect((await put(after.version, [{ kind: "model", text: model.text }])).status).toBe(200);
    const [afterSave] = await adminDb().select().from(hermesMemoryNotes).where(eq(hermesMemoryNotes.id, model.id));
    expect(afterSave?.createdAt).toEqual(beforeSave!.createdAt);
    const [audited] = await adminDb().select().from(auditLog).where(and(eq(auditLog.action, "tuning.memory"), eq(auditLog.actorId, identities[0]!))).limit(1);
    expect(JSON.stringify(audited!.detail)).not.toContain("scanner");
  });

  it("defaults to 90 days, expires all note kinds and reports, and invalidates stale memory writers", async () => {
    const before = await getMemory(admin, "alert:tune");
    expect(before.retentionDays).toBe(90);
    const cutoff = new Date(now.getTime() - 90 * DAY);
    const expired = new Date(cutoff.getTime() - 1);
    const notes = await adminDb().insert(hermesMemoryNotes).values([
      ...(["human", "model", "outcome"] as const).map((kind) => ({ kind, text: "Expired lesson", createdBy: admin.principal.userId, createdAt: expired, updatedAt: now })),
      { kind: "model" as const, text: "Boundary lesson", createdBy: admin.principal.userId, createdAt: cutoff },
    ]).returning();
    const reports = await adminDb().insert(hermesReports).values([expired, cutoff].map((createdAt) => ({ periodStart: createdAt, periodEnd: createdAt, markdown: "Old run", stats, createdBy: identities[0]!, createdAt }))).returning();
    expect(await runHermesRetention(now)).toEqual({ reports: 1 });
    const remaining = await adminDb().select().from(hermesMemoryNotes).where(inArray(hermesMemoryNotes.id, notes.map((n) => n.id)));
    expect(remaining.map((n) => n.text)).toEqual(["Boundary lesson"]);
    expect((await adminDb().select().from(hermesReports).where(inArray(hermesReports.id, reports.map((r) => r.id)))).map((r) => r.id)).toEqual([reports[1]!.id]);
    const stale = await putMemoryRoute(new Request(`${BASE}/memory`, call(tokens.hermes!, { method: "PUT", body: JSON.stringify({ version: before.version, notes: [] }) })));
    expect(stale.status).toBe(409);
    expect(await runHermesRetention(now)).toEqual({ reports: 0 });
    await adminDb().delete(hermesMemoryNotes).where(inArray(hermesMemoryNotes.id, notes.map((n) => n.id)));
    await adminDb().delete(hermesReports).where(inArray(hermesReports.id, reports.map((r) => r.id)));
  });

  it("validates and authorizes retention changes and applies shorter/longer windows", async () => {
    for (const days of [0, -1, 366, 1.5, NaN, Infinity]) await expect(setHermesRetention(admin, days)).rejects.toThrow("whole number");
    await expect(setHermesRetention({ ...admin, grants: [] }, 30)).rejects.toThrow("platform");
    const old = new Date(now.getTime() - 100 * DAY);
    const [note] = await adminDb().insert(hermesMemoryNotes).values({ kind: "human", text: "Keep for the configured window", createdBy: admin.principal.userId, createdAt: old }).returning();
    try {
      await setHermesRetention(admin, 180);
      expect((await getMemory(admin, "alert:tune")).notes.some((n) => n.id === note!.id)).toBe(true);
      await setHermesRetention(admin, 30);
      const memory = await getMemory(admin, "alert:tune");
      expect(memory.retentionDays).toBe(30);
      expect(memory.notes.some((n) => n.id === note!.id)).toBe(false);
      expect((await adminDb().select().from(hermesMemoryNotes).where(eq(hermesMemoryNotes.id, note!.id))).length).toBe(0);
    } finally {
      await setHermesRetention(admin, 90);
      await adminDb().delete(hermesMemoryNotes).where(eq(hermesMemoryNotes.id, note!.id));
    }
  });

  it("bounds total memory including analyst notes", async () => {
    const memory = await getMemory(admin, "alert:tune");
    const filler = await adminDb().insert(hermesMemoryNotes).values(Array.from({ length: 500 - memory.notes.length }, () => ({ kind: "human" as const, text: "Capacity test lesson", createdBy: admin.principal.userId }))).returning({ id: hermesMemoryNotes.id });
    try {
      await expect(addHumanNote(admin, { text: "One more analyst lesson" })).rejects.toThrow("at most 500");
      const notes = [...memory.notes.filter((n) => n.kind !== "human"), { kind: "model", text: "One more model lesson" }];
      const response = await putMemoryRoute(new Request(`${BASE}/memory`, call(tokens.hermes!, { method: "PUT", body: JSON.stringify({ version: memory.version, notes }) })));
      expect(response.status).toBe(422);
      expect((await adminDb().select().from(hermesMemoryNotes)).length).toBe(500);
    } finally {
      await adminDb().delete(hermesMemoryNotes).where(inArray(hermesMemoryNotes.id, filler.map((r) => r.id)));
    }
  });

  it("purges report backlogs across multiple bounded batches", async () => {
    const createdAt = new Date(now.getTime() - 91 * DAY);
    await adminDb().insert(hermesReports).values(Array.from({ length: 1001 }, () => ({ periodStart: createdAt, periodEnd: createdAt, markdown: "Expired report", stats, createdBy: identities[0]!, createdAt })));
    expect(await runHermesRetention(now)).toEqual({ reports: 1001 });
    expect((await listReports(admin, 5, "alert:tune")).length).toBeGreaterThan(0);
  });
});

describe("what analysts see in blakSOC", () => {
  it("shows the switch, reports, memory, actions and AI notes, and who closed an alert", async () => {
    expect((await hermesSwitchState()).enabled).toBe(true);
    expect((await listReports(admin, 5, "alert:tune")).length).toBeGreaterThan(0);
    expect((await getMemory(admin, "alert:tune")).notes.length).toBeGreaterThan(0);
    const actions = await listTuningActions(admin, [tenant]);
    expect(actions.some((a) => a.action.kind === "close" && a.tenantName === TENANT_NAME)).toBe(true);
    expect((await recentAnnotations(admin, [tenant]))[0]!.text).toBe("Nightly scanner pattern; benign.");
    const [closed] = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant), eq(alerts.status, "FALSE_POSITIVE"), isNotNull(alerts.tuningActionId))).limit(1);
    expect((await closingAction(admin, closed!))?.params.reason).toBe("Benign scanner noise");
    expect((await annotationsForAlert(admin, closed!)).length).toBe(1);
  });

  it("marks and filters the queue by what Hermes did, and links each action to its alerts", async () => {
    const scope = { tenantIds: [tenant], limit: 500 };
    const pattern = await adminDb().select({ id: alerts.id }).from(alerts).where(and(eq(alerts.tenantId, tenant), eq(alerts.ruleId, "hermes-fp")));
    const touched = await adminDb().select({ id: alerts.id, tuningActionId: alerts.tuningActionId }).from(alerts).where(and(eq(alerts.tenantId, tenant), isNotNull(alerts.tuningActionId)));

    // Closed by Hermes: its closures, including the one an analyst undid (reopened, still marked as Hermes').
    const closed = await listAlerts(admin, { ...scope, hermes: "closed" });
    expect(closed.total).toBe(touched.length);
    expect(closed.rows.every((r) => r.tuningActionId)).toBe(true);
    // The second closure re-closed some of the first one's reopened alerts; the rest still point at the undone action.
    const fromFirst = touched.filter((r) => r.tuningActionId === firstCloseAction).length;
    expect(fromFirst).toBeGreaterThan(0);
    const undoneRows = closed.rows.filter((r) => r.hermesUndoneAt);
    expect(undoneRows.length).toBe(fromFirst);
    expect(undoneRows.every((r) => hermesClosure(r) === "undone")).toBe(true);
    expect(closed.rows.filter((r) => !r.hermesUndoneAt).every((r) => hermesClosure(r) === "closed")).toBe(true);

    // Annotated: every alert on the pattern Hermes wrote a note about, and the note shows on each row.
    const annotated = await listAlerts(admin, { ...scope, hermes: "annotated" });
    expect(annotated.total).toBe(pattern.length);
    expect(annotated.rows.every((r) => r.hermesNote)).toBe(true);
    expect((await listAlerts(admin, { ...scope, hermes: "any" })).total).toBe(pattern.length);
    const others = await listAlerts(admin, scope);
    expect(others.rows.filter((r) => r.ruleId !== "hermes-fp").every((r) => !r.hermesNote && !r.tuningActionId)).toBe(true);

    // One action's alerts: a closure, an annotated pattern; unknown ids match nothing.
    const byAction = await listAlerts(admin, { ...scope, hermesAction: firstCloseAction });
    expect(byAction.total).toBe(fromFirst);
    expect(byAction.rows.every((r) => r.tuningActionId === firstCloseAction)).toBe(true);
    const [note] = await adminDb().select({ id: tuningActions.id }).from(tuningActions).where(and(eq(tuningActions.tenantId, tenant), eq(tuningActions.kind, "annotate")));
    expect((await listAlerts(admin, { ...scope, hermesAction: note!.id })).total).toBe(pattern.length);
    expect((await listAlerts(admin, { ...scope, hermesAction: randomUUID() })).total).toBe(0);
    expect(await tuningActionSummary(admin, firstCloseAction)).toMatchObject({ kind: "close", tenantName: TENANT_NAME, affectedCount: 4 });
    expect(await tuningActionSummary(admin, randomUUID())).toBeNull();

    // The closure's banner: who undid it and when.
    const reopened = await adminDb().select().from(alerts).where(eq(alerts.tuningActionId, firstCloseAction)).limit(1);
    const c = await closingAction(admin, reopened[0]!);
    expect(c).toMatchObject({ kind: "close", affectedCount: 4, undoneByKind: "user", undoneByName: admin.principal.name });
  });

  it("sums Hermes' week for the dashboard and the navigation", async () => {
    const week = await hermesWeek(admin, [tenant]);
    // This week: the first closure (4, undone), the noise rule (undone), the note and the purge (1). The second closure was moved 8 days back.
    expect(week).toMatchObject({ closed: 4, noiseRules: 1, notes: 1, purged: 1, undone: 2, inUndoWindow: 0, actions: 4 });
    // Back inside its undo window, the second closure's remaining alert counts as still undoable.
    const [second] = await adminDb().select({ id: tuningActions.id }).from(tuningActions).where(and(eq(tuningActions.tenantId, tenant), eq(tuningActions.kind, "close"), isNull(tuningActions.undoneAt)));
    await adminDb().update(tuningActions).set({ reversibleUntil: new Date(Date.now() + DAY) }).where(eq(tuningActions.id, second!.id));
    expect((await hermesWeek(admin, [tenant])).inUndoWindow).toBe(1);
    expect(await hermesRecentActionCount(admin)).toBeGreaterThanOrEqual(4);
  });
});
