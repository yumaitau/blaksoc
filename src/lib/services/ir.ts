import { and, desc, eq, sql } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { escalationPolicies, irExercises, irPlans, obligationCases, tenants } from "@/db/schema";
import { audit } from "@/lib/audit";
import type { AccessContext } from "@/lib/auth/access";
import { docxBytes } from "@/lib/ir/docx";
import { IR_SCENARIOS, irScenarioById } from "@/lib/ir/scenarios";
import { toPdf } from "@/lib/reports/export";
import type { ReportContent } from "@/lib/reports/types";
import { actor, inTenant } from "./common";

export class IrError extends Error {
  constructor(readonly code: "scenario" | "version") {
    super(code);
    this.name = "IrError";
  }
}

export type IrPlanInput = {
  culturalProtocol: string;
  bank: string;
  insurer: string;
  itProvider: string;
};

const blank = (value: string) => {
  const text = value.trim();
  return text.length ? text.slice(0, 500) : "Not recorded";
};

export function listIrScenarios() {
  return IR_SCENARIOS.map(({ id, title, summary }) => ({ id, title, summary }));
}

async function contactsOf(tx: Tx, tenantId: string) {
  const [policy] = await tx.select({ steps: escalationPolicies.steps }).from(escalationPolicies).where(eq(escalationPolicies.tenantId, tenantId));
  const contacts = [...new Set((policy?.steps ?? []).flatMap((step) => step.contacts))].filter(Boolean);
  return contacts.length ? contacts.join(", ") : "No escalation contacts are saved.";
}

async function openObligations(tx: Tx, tenantId: string) {
  const [row] = await tx
    .select({ n: sql<number>`count(*)::int` })
    .from(obligationCases)
    .where(and(eq(obligationCases.tenantId, tenantId), sql`${obligationCases.decision} is null`));
  return Number(row?.n ?? 0);
}

function planParagraphs(input: {
  tenantName: string;
  version: number;
  culturalProtocol: string;
  bank: string;
  insurer: string;
  itProvider: string;
  contacts: string;
  obligations: number;
}): string[] {
  return [
    `Incident response plan. Version ${input.version}.`,
    input.tenantName,
    `Who speaks to community: ${blank(input.culturalProtocol)}`,
    `Bank: ${blank(input.bank)}`,
    `Insurer: ${blank(input.insurer)}`,
    `IT provider: ${blank(input.itProvider)}`,
    `Escalation contacts: ${input.contacts}`,
    `Open obligation cases: ${input.obligations}.`,
    "A customer administrator can approve containment.",
    "This plan has not been reviewed by an advisory group.",
    ...IR_SCENARIOS.map((scenario) => `${scenario.title}. ${scenario.summary}`),
  ];
}

export async function saveIrPlan(ctx: AccessContext, tenantId: string, input: IrPlanInput) {
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const [max] = await tx.select({ version: sql<number>`coalesce(max(${irPlans.version}), 0)::int` }).from(irPlans).where(eq(irPlans.tenantId, tenantId));
    const version = Number(max?.version ?? 0) + 1;
    const [row] = await tx.insert(irPlans).values({
      tenantId,
      version,
      culturalProtocol: input.culturalProtocol.trim().slice(0, 500),
      bank: input.bank.trim().slice(0, 500),
      insurer: input.insurer.trim().slice(0, 500),
      itProvider: input.itProvider.trim().slice(0, 500),
    }).returning({ id: irPlans.id });
    if (!row) throw new IrError("version");
    await audit(tx, { ...actor(ctx), tenantId, action: "ir.plan", targetType: "ir_plan", targetId: row.id, detail: { version } });
    return { id: row.id, version };
  });
}

export async function latestIrPlan(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const [row] = await tx.select().from(irPlans).where(eq(irPlans.tenantId, tenantId)).orderBy(desc(irPlans.version)).limit(1);
    return row ?? null;
  });
}

async function paragraphsFor(tx: Tx, tenantId: string, version: number) {
  const [plan] = await tx.select().from(irPlans).where(and(eq(irPlans.tenantId, tenantId), eq(irPlans.version, version)));
  if (!plan) throw new IrError("version");
  const [tenant] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, tenantId));
  return planParagraphs({
    tenantName: tenant?.name ?? "Tenant",
    version: plan.version,
    culturalProtocol: plan.culturalProtocol,
    bank: plan.bank,
    insurer: plan.insurer,
    itProvider: plan.itProvider,
    contacts: await contactsOf(tx, tenantId),
    obligations: await openObligations(tx, tenantId),
  });
}

export async function exportIrPlan(ctx: AccessContext, tenantId: string, version: number, format: "pdf" | "docx") {
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const paragraphs = await paragraphsFor(tx, tenantId, version);
    if (format === "docx") return { format, bytes: docxBytes(paragraphs) };
    const content: ReportContent = {
      tenantName: paragraphs[1] ?? "Tenant",
      generatedAt: new Date().toISOString(),
      period: { start: new Date().toISOString(), end: new Date().toISOString() },
      sections: paragraphs.map((body, index) => ({ heading: index === 0 ? "Incident response plan" : `Part ${index}`, basis: "observed" as const, body })),
    };
    return { format, bytes: await toPdf("Incident response plan", content) };
  });
}

export async function completeExercise(ctx: AccessContext, tenantId: string, scenarioId: string, input: { notes: string; lessons: string }, now = new Date()) {
  const scenario = irScenarioById(scenarioId);
  if (!scenario) throw new IrError("scenario");
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const [row] = await tx.insert(irExercises).values({
      tenantId,
      scenarioId: scenario.id,
      completedAt: now,
      notes: input.notes.trim().slice(0, 1000),
      lessons: input.lessons.trim().slice(0, 1000),
    }).returning({ id: irExercises.id });
    if (!row) throw new IrError("scenario");
    await audit(tx, { ...actor(ctx), tenantId, action: "ir.exercise", targetType: "ir_exercise", targetId: row.id, detail: { scenarioId: scenario.id } });
    return { id: row.id, title: scenario.title };
  });
}

export async function listRecordedExercises(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "report:generate", tenantId, (tx) => exerciseTitles(tx, tenantId));
}

export async function exerciseTitles(tx: Tx, tenantId: string) {
  const rows = await tx.select({ scenarioId: irExercises.scenarioId }).from(irExercises).where(eq(irExercises.tenantId, tenantId));
  return rows.map((row) => irScenarioById(row.scenarioId)?.title ?? row.scenarioId);
}
