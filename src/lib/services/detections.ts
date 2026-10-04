import { and, desc, eq, inArray, isNull, or, sql } from "drizzle-orm";
import { alerts, attackTechniques, user, detectionDeployments, incidents, integrations, integrationTenantLinks, sigmaRules, sigmaRuleTests, sigmaRuleVersions } from "@/db/schema";
import { withScope } from "@/db/scope";
import { assertCan, can, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { sha256 } from "@/lib/crypto";
import type { Tx } from "@/db/client";
import { eventProvider } from "@/lib/connectors/instances";
import { attackTechniques as sigmaTechniques, parseSigma, runTests, toOpenSearchQuery } from "@/lib/detections/sigma";
import { actor, AccessDenied, scoped } from "./common";

/** Rules visible to the caller: global rules plus tenant rules in scope. */
export async function listRules(ctx: AccessContext, opts: { tenantId?: string | null } = {}) {
  return scoped(ctx, "detection:read", (tx, tenantIds) =>
    tx
      .select({
        rule: sigmaRules,
        deployments: sql<number>`(select count(*)::int from ${detectionDeployments} d where d.rule_id = ${sigmaRules.id} and d.status = 'active')`,
      })
      .from(sigmaRules)
      .where(opts.tenantId === null ? isNull(sigmaRules.tenantId) : opts.tenantId ? eq(sigmaRules.tenantId, opts.tenantId) : or(isNull(sigmaRules.tenantId), inArray(sigmaRules.tenantId, tenantIds)))
      .orderBy(desc(sigmaRules.updatedAt)),
  );
}

export async function getRule(ctx: AccessContext, id: string) {
  return scoped(ctx, "detection:read", async (tx) => {
    const [rule] = await tx.select().from(sigmaRules).where(eq(sigmaRules.id, id));
    if (!rule) return null;
    const [versions, tests, deployments] = await Promise.all([
      tx.select().from(sigmaRuleVersions).where(eq(sigmaRuleVersions.ruleId, id)).orderBy(desc(sigmaRuleVersions.version)),
      tx.select().from(sigmaRuleTests).where(eq(sigmaRuleTests.ruleId, id)).orderBy(desc(sigmaRuleTests.createdAt)).limit(20),
      tx.select().from(detectionDeployments).where(eq(detectionDeployments.ruleId, id)),
    ]);
    return { rule, versions, tests, deployments };
  });
}

/** Create a rule or a new version. Global rules (tenantId null) need platform detection:write. */
export async function saveRule(ctx: AccessContext, input: { id?: string; tenantId: string | null; yaml: string; changeNote?: string; confidence?: number }) {
  const parsed = parseSigma(input.yaml);
  if (input.tenantId) assertCan(ctx, "detection:write", input.tenantId);
  else if (!(ctx.isPlatform && can(ctx, "detection:write"))) throw new AccessDenied("global rules require platform detection:write");

  const scope = { tenantIds: input.tenantId ? [input.tenantId] : [], platform: !input.tenantId };
  return withScope(scope, async (tx) => {
    const head = {
      sigmaId: parsed.id,
      title: parsed.title,
      description: parsed.description ?? null,
      status: parsed.status ?? "experimental",
      severity: parsed.level ?? "medium",
      logsource: parsed.logsource,
      attackTechniques: sigmaTechniques(parsed),
      falsePositives: parsed.falsepositives ?? [],
      ...(input.confidence != null ? { confidence: input.confidence } : {}),
      updatedAt: new Date(),
    };
    let ruleId = input.id;
    let version = 1;
    if (ruleId) {
      const [cur] = await tx.select().from(sigmaRules).where(eq(sigmaRules.id, ruleId));
      if (!cur) throw new AccessDenied("rule not found");
      version = cur.currentVersion + 1;
      await tx.update(sigmaRules).set({ ...head, currentVersion: version }).where(eq(sigmaRules.id, ruleId));
    } else {
      const [row] = await tx.insert(sigmaRules).values({ ...head, tenantId: input.tenantId, createdBy: ctx.principal.userId }).returning({ id: sigmaRules.id });
      ruleId = row!.id;
    }
    await tx.insert(sigmaRuleVersions).values({ ruleId, tenantId: input.tenantId, version, yaml: input.yaml, sha256: sha256(input.yaml), changeNote: input.changeNote ?? null, createdBy: ctx.principal.userId });
    await audit(tx, { ...actor(ctx), tenantId: input.tenantId, action: "detection.save", targetType: "sigma_rule", targetId: ruleId, detail: { version, title: parsed.title } });
    return { id: ruleId, version };
  });
}

export async function setRuleEnabled(ctx: AccessContext, id: string, enabled: boolean) {
  return scoped(ctx, "detection:write", async (tx) => {
    const [r] = await tx.update(sigmaRules).set({ enabled, updatedAt: new Date() }).where(eq(sigmaRules.id, id)).returning();
    if (!r) throw new AccessDenied("rule not found or not writable");
    if (!enabled) await tx.update(detectionDeployments).set({ status: "paused" }).where(eq(detectionDeployments.ruleId, id));
    await audit(tx, { ...actor(ctx), tenantId: r.tenantId, action: enabled ? "detection.enable" : "detection.disable", targetType: "sigma_rule", targetId: id });
    return r;
  });
}

export async function testRule(ctx: AccessContext, id: string, cases: { name: string; event: Record<string, unknown>; expect: boolean }[]) {
  return scoped(ctx, "detection:write", async (tx) => {
    const [r] = await tx.select().from(sigmaRules).where(eq(sigmaRules.id, id));
    if (!r) throw new AccessDenied("rule not found");
    const [v] = await tx.select().from(sigmaRuleVersions).where(and(eq(sigmaRuleVersions.ruleId, id), eq(sigmaRuleVersions.version, r.currentVersion)));
    const { results, passed } = runTests(parseSigma(v!.yaml), cases);
    // Test history for global rules is recorded by platform staff only (RLS global_write).
    if (r.tenantId || ctx.isPlatform) {
      await tx.insert(sigmaRuleTests).values({ ruleId: id, tenantId: r.tenantId, version: r.currentVersion, cases, results, passed, ranBy: ctx.principal.userId });
    }
    return { results, passed };
  });
}

/** The tenant's own enabled integration that imports Sigma itself (e.g. Tawny), if any. */
async function pushTarget(tx: Tx, tenantId: string) {
  const rows = await tx.select().from(integrations).where(and(eq(integrations.tenantId, tenantId), eq(integrations.enabled, true)));
  for (const row of rows) {
    try {
      const provider = eventProvider(row);
      if (provider.deployDetection) return { row, provider };
    } catch {
      /* not an event provider */
    }
  }
  return null;
}

/**
 * Deploy the current version for each target tenant. A tenant linked to a shared SIEM gets a scheduled
 * Wazuh-indexer query. Otherwise, a tenant-owned integration that imports Sigma itself (Tawny) receives
 * the YAML, and a rejection aborts the deployment with the provider's reason.
 */
export async function deployRule(ctx: AccessContext, id: string, tenantIds: string[]) {
  for (const t of tenantIds) assertCan(ctx, "detection:deploy", t);
  return withScope({ tenantIds, platform: false }, async (tx) => {
    const [r] = await tx.select().from(sigmaRules).where(eq(sigmaRules.id, id));
    if (!r) throw new AccessDenied("rule not found");
    if (r.tenantId && tenantIds.some((t) => t !== r.tenantId)) throw new AccessDenied("tenant rules deploy only to their own tenant");
    const [v] = await tx.select().from(sigmaRuleVersions).where(and(eq(sigmaRuleVersions.ruleId, id), eq(sigmaRuleVersions.version, r.currentVersion)));
    const rule = parseSigma(v!.yaml);
    const tests = await tx.select().from(sigmaRuleTests).where(and(eq(sigmaRuleTests.ruleId, id), eq(sigmaRuleTests.version, r.currentVersion))).orderBy(desc(sigmaRuleTests.createdAt)).limit(1);
    if (r.status !== "experimental" && tests[0] && !tests[0].passed) throw new Error("latest test run for this version failed; fix before deploying");
    const query = toOpenSearchQuery(rule);
    const pushed: { tenantId: string; integration: string; message: string }[] = [];
    for (const tenantId of tenantIds) {
      const [link] = await tx.select({ integrationId: integrationTenantLinks.integrationId }).from(integrationTenantLinks).where(eq(integrationTenantLinks.tenantId, tenantId)).limit(1);
      let integrationId = link?.integrationId ?? null;
      let stored = query;
      const target = link ? null : await pushTarget(tx, tenantId);
      if (target) {
        const res = await target.provider.deployDetection!(v!.yaml);
        integrationId = target.row.id;
        stored = `${target.row.provider}:alert-rule:${res.providerRef}`;
        pushed.push({ tenantId, integration: target.row.name, message: res.message });
      }
      await tx
        .insert(detectionDeployments)
        .values({ ruleId: id, tenantId, integrationId, version: r.currentVersion, query: stored, deployedBy: ctx.principal.userId })
        .onConflictDoUpdate({ target: [detectionDeployments.ruleId, detectionDeployments.tenantId], set: { version: r.currentVersion, query: stored, ...(target ? { integrationId } : {}), status: "active", deployedBy: ctx.principal.userId, deployedAt: new Date() } });
      await audit(tx, { ...actor(ctx), tenantId, action: "detection.deploy", targetType: "sigma_rule", targetId: id, detail: { version: r.currentVersion, ...(target ? { integrationId, providerRef: stored } : {}) } });
    }
    return { query, deployed: tenantIds.length, pushed };
  });
}

export type CoverageCell = {
  id: string;
  name: string;
  tactics: string[];
  parentId: string | null;
  rules: number;
  deployed: number;
  alerts: number;
  incidents: number;
};

/** ATT&CK coverage: detections available/deployed vs activity observed, per technique. */
export async function attackCoverage(ctx: AccessContext, tenantIds?: string[]): Promise<CoverageCell[]> {
  return scoped(
    ctx,
    "detection:read",
    async (tx, scopeTenants) => {
      const techniques = await tx.select().from(attackTechniques);
      const rules = await tx.select({ techniques: sigmaRules.attackTechniques, tenantId: sigmaRules.tenantId, enabled: sigmaRules.enabled }).from(sigmaRules).where(or(isNull(sigmaRules.tenantId), inArray(sigmaRules.tenantId, scopeTenants)));
      const deployed = await tx.select({ techniques: sigmaRules.attackTechniques }).from(detectionDeployments).innerJoin(sigmaRules, eq(sigmaRules.id, detectionDeployments.ruleId)).where(and(inArray(detectionDeployments.tenantId, scopeTenants), eq(detectionDeployments.status, "active")));
      const alertRows = await tx.select({ t: sql<string>`unnest(${alerts.attackTechniques})`, n: sql<number>`count(*)::int` }).from(alerts).where(and(inArray(alerts.tenantId, scopeTenants), sql`${alerts.occurredAt} > now() - interval '90 days'`)).groupBy(sql`1`);
      const incRows = await tx.select({ t: sql<string>`unnest(${incidents.attackTechniques})`, n: sql<number>`count(*)::int` }).from(incidents).where(inArray(incidents.tenantId, scopeTenants)).groupBy(sql`1`);

      const count = (list: string[][], id: string) => list.filter((ts) => ts.some((t) => t === id || t.startsWith(`${id}.`))).length;
      const ruleTech = rules.filter((r) => r.enabled).map((r) => r.techniques);
      const depTech = deployed.map((d) => d.techniques);
      const sumBy = (rows: { t: string; n: number }[], id: string) => rows.filter((r) => r.t === id || r.t.startsWith(`${id}.`)).reduce((s, r) => s + r.n, 0);
      return techniques.map((t) => ({
        id: t.id, name: t.name, tactics: t.tactics, parentId: t.parentId,
        rules: count(ruleTech, t.id), deployed: count(depTech, t.id), alerts: sumBy(alertRows, t.id), incidents: sumBy(incRows, t.id),
      }));
    },
    tenantIds,
  );
}

export async function detectionIntegrations(ctx: AccessContext) {
  return scoped(ctx, "detection:read", (tx) => tx.select({ id: integrations.id, name: integrations.name }).from(integrations).where(eq(integrations.provider, "wazuh")));
}

/** Display names for rule authors / deployers (user ids stored on versions, tests, deployments). */
export async function authorNames(ctx: AccessContext, userIds: (string | null)[]): Promise<Map<string, string>> {
  assertCan(ctx, "detection:read");
  const ids = [...new Set(userIds.filter((u): u is string => !!u))];
  if (!ids.length) return new Map();
  const rows = await withScope({ tenantIds: ctx.tenantIds, platform: ctx.isPlatform }, (tx) => tx.select({ id: user.id, name: user.name }).from(user).where(inArray(user.id, ids)));
  return new Map(rows.map((r) => [r.id, r.name]));
}
