import { and, eq, inArray } from "drizzle-orm";
import { alerts, DEFAULT_TENANT_SETTINGS, integrations, tenants, trainingAttempts, trainingCosigns } from "@/db/schema";
import type { Tx } from "@/db/client";
import { withScope } from "@/db/scope";
import { audit } from "@/lib/audit";
import { can, type AccessContext } from "@/lib/auth/access";
import { DemoProvider } from "@/lib/providers/demo";
import { scenarioById } from "@/lib/training/scenarios";
import { scoreAttempt, TRAINEE_ACTIONS, type TraineeAction } from "@/lib/training/score";
import { actor, AccessDenied, inTenant } from "./common";
import { createIntegration } from "./integrations";

export class TrainingError extends Error {
  constructor(readonly code: "scenario" | "tenant" | "demo" | "attempt" | "action" | "hint" | "slug") {
    super(code);
    this.name = "TrainingError";
  }
}

export const TRAINING_AGENT = { id: "train-1", name: "training-pc", group: "training", os: "Windows 11", ip: "203.0.113.50" };

type Agent = { id: string; name: string; group: string; os: string; ip: string };

function agentsOf(config: Record<string, unknown>): Agent[] {
  const agents = config.agents;
  if (!Array.isArray(agents) || agents.length === 0) return [];
  return agents.filter((agent): agent is Agent => {
    if (!agent || typeof agent !== "object") return false;
    const row = agent as Record<string, unknown>;
    return typeof row.id === "string" && typeof row.name === "string" && typeof row.group === "string" && typeof row.os === "string" && typeof row.ip === "string";
  });
}

/** Open a customer tenant that can only carry the demo provider. */
export async function openTrainingTenant(ctx: AccessContext, input: { name: string; slug: string }) {
  if (!ctx.isPlatform || !can(ctx, "tenant:manage")) throw new AccessDenied("platform tenant:manage required");
  if (!/^[a-z0-9-]{2,40}$/.test(input.slug)) throw new TrainingError("slug");
  const tenant = await withScope({ tenantIds: [], platform: true }, async (tx) => {
    const [row] = await tx
      .insert(tenants)
      .values({ name: input.name, slug: input.slug, kind: "customer", settings: { ...DEFAULT_TENANT_SETTINGS, training: true } })
      .returning();
    if (!row) throw new TrainingError("tenant");
    await audit(tx, { ...actor(ctx), tenantId: null, action: "training.open", targetType: "tenant", targetId: row.id, detail: { slug: input.slug } });
    return row;
  });
  const integrationId = await createIntegration({
    ...ctx,
    tenantIds: ctx.tenantIds.includes(tenant.id) ? ctx.tenantIds : [...ctx.tenantIds, tenant.id],
    tenants: ctx.tenants.some((row) => row.id === tenant.id) ? ctx.tenants : [...ctx.tenants, { id: tenant.id, slug: tenant.slug, name: tenant.name, kind: "customer" }],
  }, {
    tenantId: tenant.id,
    provider: "demo",
    name: "Training demo",
    config: { agents: [TRAINING_AGENT] },
    secrets: {},
  });
  return { tenantId: tenant.id, integrationId };
}

/** Replay one authored scenario through the demo provider onto the training queue. */
export async function startScenario(ctx: AccessContext, tenantId: string, scenarioId: string, trainee: { id: string; name: string }, now = new Date()) {
  const scenario = scenarioById(scenarioId);
  if (!scenario) throw new TrainingError("scenario");
  const name = trainee.name.trim();
  if (!trainee.id.trim() || name.length < 1) throw new TrainingError("attempt");
  return inTenant(ctx, "alert:triage", tenantId, async (tx) => {
    const [tenant] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, tenantId));
    if (!tenant?.settings.training) throw new TrainingError("tenant");
    const [integration] = await tx
      .select({ id: integrations.id, config: integrations.config })
      .from(integrations)
      .where(and(eq(integrations.tenantId, tenantId), eq(integrations.provider, "demo")));
    const agents = integration ? agentsOf(integration.config) : [];
    const agent = agents[0];
    if (!integration || !agent) throw new TrainingError("demo");
    const provider = new DemoProvider(agents);
    const titles: string[] = [];
    for (let i = 0; i < scenario.events.length; i += 1) {
      const spec = scenario.events[i]!;
      const alert = provider.materialise(spec, agent, `training:${scenario.id}:${trainee.id}:${i}`, now, i);
      titles.push(alert.title);
      await tx
        .insert(alerts)
        .values({
          tenantId,
          integrationId: integration.id,
          source: "demo",
          externalId: alert.externalId,
          ruleId: alert.ruleId,
          title: alert.title,
          description: alert.description,
          category: alert.category,
          siemSeverity: alert.siemSeverity,
          severity: alert.severity,
          userName: alert.userName,
          attackTechniques: alert.attackTechniques,
          raw: alert.raw,
          occurredAt: alert.occurredAt,
          status: "NEW",
        })
        .onConflictDoNothing();
    }
    const [attempt] = await tx
      .insert(trainingAttempts)
      .values({ tenantId, scenarioId: scenario.id, traineeId: trainee.id, traineeName: name })
      .returning({ id: trainingAttempts.id });
    if (!attempt) throw new TrainingError("attempt");
    await audit(tx, { ...actor(ctx), tenantId, action: "training.start", targetType: "training_attempt", targetId: attempt.id, detail: { scenarioId: scenario.id, traineeId: trainee.id } });
    return { attemptId: attempt.id, hints: scenario.hints, titles };
  });
}

export async function useHint(ctx: AccessContext, tenantId: string, attemptId: string) {
  return inTenant(ctx, "alert:triage", tenantId, async (tx) => {
    const [row] = await tx.select().from(trainingAttempts).where(and(eq(trainingAttempts.id, attemptId), eq(trainingAttempts.tenantId, tenantId)));
    if (!row || row.status !== "open") throw new TrainingError("attempt");
    const scenario = scenarioById(row.scenarioId);
    if (!scenario || row.hintsUsed >= scenario.hints.length) throw new TrainingError("hint");
    const hint = scenario.hints[row.hintsUsed]!;
    await tx.update(trainingAttempts).set({ hintsUsed: row.hintsUsed + 1 }).where(eq(trainingAttempts.id, row.id));
    return hint;
  });
}

export async function recordAction(ctx: AccessContext, tenantId: string, attemptId: string, action: TraineeAction) {
  if (!TRAINEE_ACTIONS.includes(action)) throw new TrainingError("action");
  return inTenant(ctx, "alert:triage", tenantId, async (tx) => {
    const [row] = await tx.select().from(trainingAttempts).where(and(eq(trainingAttempts.id, attemptId), eq(trainingAttempts.tenantId, tenantId)));
    if (!row || row.status !== "open") throw new TrainingError("attempt");
    const scenario = scenarioById(row.scenarioId);
    if (!scenario) throw new TrainingError("scenario");
    const actions = [...row.actions, action];
    const done = actions.length >= scenario.expected.length;
    const score = done ? scoreAttempt(scenario.expected, actions, row.hintsUsed) : 0;
    await tx.update(trainingAttempts).set({ actions, score, status: done ? "scored" : "open" }).where(eq(trainingAttempts.id, row.id));
    return { actions, score, status: done ? "scored" : "open" };
  });
}

async function progressFrom(tx: Tx, tenantId: string) {
  const attempts = await tx.select().from(trainingAttempts).where(eq(trainingAttempts.tenantId, tenantId));
  const cosigns = await tx.select({ traineeId: trainingCosigns.traineeId }).from(trainingCosigns).where(eq(trainingCosigns.tenantId, tenantId));
  const signed = new Set(cosigns.map((row) => row.traineeId));
  const grouped = new Map<string, typeof attempts>();
  for (const attempt of attempts) {
    const list = grouped.get(attempt.traineeId) ?? [];
    list.push(attempt);
    grouped.set(attempt.traineeId, list);
  }
  const trainees = [...grouped.entries()].map(([traineeId, rows]) => {
    const scored = rows.filter((row) => row.status === "scored");
    const averageScore = scored.length ? Math.round(scored.reduce((sum, row) => sum + row.score, 0) / scored.length) : 0;
    const skills = new Map<string, boolean>();
    for (const row of rows) {
      const scenario = scenarioById(row.scenarioId);
      if (!scenario) continue;
      for (const skill of scenario.skills) {
        skills.set(skill, (skills.get(skill) ?? false) || (row.status === "scored" && row.score >= 80));
      }
    }
    return {
      traineeId,
      traineeName: rows[0]!.traineeName,
      attempts: rows.length,
      averageScore,
      skills: [...skills.entries()].map(([skill, passed]) => ({ skill, passed })),
      cosigned: signed.has(traineeId),
    };
  });
  return { trainees };
}

/** Scores and co-signs for mentors. Trainees do not hold alert:assign. */
export async function mentorProgress(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "alert:assign", tenantId, async (tx) => {
    const [tenant] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, tenantId));
    if (!tenant?.settings.training) throw new TrainingError("tenant");
    return progressFrom(tx, tenantId);
  });
}

export async function mentorBoard(ctx: AccessContext) {
  if (!ctx.isPlatform || !can(ctx, "alert:assign")) throw new AccessDenied("missing alert:assign");
  const ids = ctx.tenantIds;
  if (!ids.length) return [];
  return withScope({ tenantIds: ids, grantIds: ids, platform: true }, async (tx) => {
    const rows = await tx.select({ id: tenants.id, name: tenants.name, settings: tenants.settings }).from(tenants).where(and(inArray(tenants.id, ids), eq(tenants.kind, "customer")));
    const board = [];
    for (const tenant of rows) {
      if (!tenant.settings.training) continue;
      if (!ids.includes(tenant.id)) continue;
      const progress = await progressFrom(tx, tenant.id);
      board.push({ id: tenant.id, name: tenant.name, trainees: progress.trainees });
    }
    return board;
  });
}

/** Record a mentor co-sign. Does not grant a role on any customer tenant. */
export async function cosignTrainee(ctx: AccessContext, tenantId: string, traineeId: string) {
  return inTenant(ctx, "alert:assign", tenantId, async (tx) => {
    const [tenant] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, tenantId));
    if (!tenant?.settings.training) throw new TrainingError("tenant");
    const [attempt] = await tx
      .select({ id: trainingAttempts.id })
      .from(trainingAttempts)
      .where(and(eq(trainingAttempts.tenantId, tenantId), eq(trainingAttempts.traineeId, traineeId)));
    if (!attempt) throw new TrainingError("attempt");
    await tx
      .insert(trainingCosigns)
      .values({ tenantId, traineeId, mentorId: ctx.principal.userId })
      .onConflictDoUpdate({ target: [trainingCosigns.tenantId, trainingCosigns.traineeId], set: { mentorId: ctx.principal.userId, cosignedAt: new Date() } });
    await audit(tx, { ...actor(ctx), tenantId, action: "training.cosign", targetType: "training_cosign", targetId: traineeId, detail: { traineeId } });
    return true;
  });
}
