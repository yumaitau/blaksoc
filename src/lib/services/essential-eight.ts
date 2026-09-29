import { and, desc, eq } from "drizzle-orm";
import { assets, cveIntel, e8Assessments, e8Tasks, integrations, tenants, vulnerabilities } from "@/db/schema";
import type { Tx } from "@/db/client";
import { audit } from "@/lib/audit";
import type { AccessContext } from "@/lib/auth/access";
import { evidenceFromTelemetry, type OfficeMacroSnapshot, type TelemetrySnapshot } from "@/lib/essential-eight/evidence";
import { buildAssessmentReport } from "@/lib/essential-eight/report";
import { answerIds, CADENCE_DAYS, type CadenceDays } from "@/lib/essential-eight/requirements";
import { levelTrend, levelsOf, scoreEssentialEight, type AssessmentResult } from "@/lib/essential-eight/score";
import { toPdf } from "@/lib/reports/export";
import { actor, inTenant } from "./common";

export class EssentialEightError extends Error {
  constructor(readonly code: "incomplete" | "owner" | "cadence" | "missing") {
    super(code);
  }
}

const MACRO_FIELDS = ["disabledWithoutNeed", "internetBlocked", "antivirusScan", "usersCannotChange", "win32Blocked"] as const;

function flag(attrs: Record<string, unknown> | null, key: string): boolean | null {
  const value = attrs?.[key];
  return typeof value === "boolean" ? value : null;
}

function readMacros(config: Record<string, unknown>): OfficeMacroSnapshot | null {
  const raw = config.officeMacros;
  if (!raw || typeof raw !== "object") return null;
  const source = raw as Record<string, unknown>;
  const out: OfficeMacroSnapshot = {};
  let any = false;
  for (const key of MACRO_FIELDS) {
    if (typeof source[key] === "boolean") {
      out[key] = source[key];
      any = true;
    }
  }
  return any ? out : null;
}

function mergeMacros(current: OfficeMacroSnapshot | null, next: OfficeMacroSnapshot): OfficeMacroSnapshot {
  const out: OfficeMacroSnapshot = { ...current };
  for (const key of MACRO_FIELDS) {
    if (next[key] === false) out[key] = false;
    else if (out[key] === undefined && next[key] !== undefined) out[key] = next[key];
  }
  return out;
}

async function loadSnapshot(tx: Tx, tenantId: string): Promise<TelemetrySnapshot> {
  const assetRows = await tx
    .select({ kind: assets.kind, exposure: assets.exposure, privileged: assets.privileged, attributes: assets.attributes })
    .from(assets)
    .where(eq(assets.tenantId, tenantId));
  const vulnRows = await tx
    .select({
      cve: vulnerabilities.cve,
      cvss: vulnerabilities.cvss,
      firstSeen: vulnerabilities.firstSeen,
      kind: assets.kind,
      exposure: assets.exposure,
      kev: cveIntel.kev,
      intelCvss: cveIntel.cvss,
    })
    .from(vulnerabilities)
    .innerJoin(assets, eq(assets.id, vulnerabilities.assetId))
    .leftJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve))
    .where(and(eq(vulnerabilities.tenantId, tenantId), eq(vulnerabilities.status, "open")));
  const connectorRows = await tx
    .select({ provider: integrations.provider, config: integrations.config })
    .from(integrations)
    .where(eq(integrations.tenantId, tenantId));

  let officeMacros: OfficeMacroSnapshot | null = null;
  for (const row of connectorRows) {
    if (row.provider !== "intune" && row.provider !== "gpo") continue;
    const parsed = readMacros(row.config);
    if (parsed) officeMacros = mergeMacros(officeMacros, parsed);
  }

  return {
    assets: assetRows.filter((row) => row.kind !== "identity").map((row) => ({ kind: row.kind, exposure: row.exposure })),
    vulns: vulnRows.map((row) => ({
      cve: row.cve,
      cvss: row.cvss ?? row.intelCvss ?? null,
      kev: row.kev ?? false,
      firstSeen: row.firstSeen,
      kind: row.kind,
      exposure: row.exposure,
    })),
    identities: assetRows.filter((row) => row.kind === "identity").map((row) => ({
      privileged: row.privileged,
      mfa: flag(row.attributes, "mfa"),
      internetAccess: flag(row.attributes, "internetAccess"),
    })),
    connectors: connectorRows.map((row) => row.provider),
    officeMacros,
  };
}

export async function submitEssentialEight(
  ctx: AccessContext,
  tenantId: string,
  input: { answers: Record<string, string>; owner: string; cadenceDays: number; assessedAt?: Date },
) {
  const owner = input.owner.trim();
  if (!owner || owner.length > 200) throw new EssentialEightError("owner");
  if (!(CADENCE_DAYS as readonly number[]).includes(input.cadenceDays)) throw new EssentialEightError("cadence");
  const answers: Record<string, "yes" | "no"> = {};
  for (const id of answerIds()) {
    const raw = input.answers[id];
    if (raw !== "yes" && raw !== "no") throw new EssentialEightError("incomplete");
    answers[id] = raw;
  }
  const assessedAt = input.assessedAt ?? new Date();
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const bundle = evidenceFromTelemetry(await loadSnapshot(tx, tenantId), assessedAt);
    const scored = scoreEssentialEight({
      answers,
      evidence: bundle.items,
      telemetry: bundle.telemetry,
      assessedAt,
      owner,
      cadenceDays: input.cadenceDays,
    });
    const [prev] = await tx.select().from(e8Assessments).where(eq(e8Assessments.tenantId, tenantId)).orderBy(desc(e8Assessments.assessedAt)).limit(1);
    const previous = prev ? { assessedAt: prev.assessedAt.toISOString(), levels: levelsOf(prev.result.ratings) } : null;
    const result: AssessmentResult = {
      disclaimer: scored.disclaimer,
      model: scored.model,
      assessedAt: assessedAt.toISOString(),
      cadenceDays: input.cadenceDays as CadenceDays,
      nextDue: scored.nextDue.toISOString(),
      owner,
      telemetry: bundle.telemetry,
      ratings: scored.ratings,
      remediation: scored.remediation,
      previous,
      trend: levelTrend(levelsOf(scored.ratings), previous?.levels ?? null),
    };
    const [row] = await tx.insert(e8Assessments).values({
      tenantId,
      assessedAt,
      cadenceDays: input.cadenceDays,
      nextDue: scored.nextDue,
      owner,
      answers,
      result,
    }).returning();
    if (result.remediation.length) {
      await tx.insert(e8Tasks).values(result.remediation.map((item) => ({
        tenantId,
        assessmentId: row!.id,
        requirementId: item.requirementId,
        strategy: item.strategy,
        title: item.title,
        owner: item.owner,
        dueAt: new Date(item.dueAt),
        priority: item.priority,
      })));
    }
    await audit(tx, { ...actor(ctx), tenantId, action: "e8.assess", targetType: "e8_assessment", targetId: row!.id, detail: { levels: levelsOf(scored.ratings) } });
    return { id: row!.id, result };
  });
}

export async function latestEssentialEight(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const [row] = await tx.select().from(e8Assessments).where(eq(e8Assessments.tenantId, tenantId)).orderBy(desc(e8Assessments.assessedAt)).limit(1);
    return row ?? null;
  });
}

export async function assessmentPdf(ctx: AccessContext, tenantId: string, assessmentId: string) {
  return inTenant(ctx, "report:generate", tenantId, async (tx) => {
    const [row] = await tx.select().from(e8Assessments).where(and(eq(e8Assessments.id, assessmentId), eq(e8Assessments.tenantId, tenantId)));
    if (!row) throw new EssentialEightError("missing");
    const [tenant] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, tenantId));
    return toPdf("Essential Eight self-assessment", buildAssessmentReport(tenant?.name ?? "Tenant", row.result));
  });
}
