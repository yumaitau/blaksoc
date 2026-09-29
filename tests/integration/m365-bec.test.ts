/**
 * Demo tenant seeded with recorded Graph fixtures (pnpm db:seed, DEMO_MODE=true).
 * Drives the Suspected BEC playbook through the real approval and response path.
 */
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import {
  alerts, approvals, assets, auditLog, incidentTasks, incidentTimeline, integrations, playbookRuns, playbookRunSteps, playbooks, sigmaRuleTests, sigmaRules, tenants, user,
} from "@/db/schema";
import { resolveAccess, type AccessContext } from "@/lib/auth/access";
import { BEC_DETECTIONS } from "@/lib/detections/bec";
import { parseSigma } from "@/lib/detections/sigma";
import { connectorDef } from "@/lib/connectors/registry";
import { eventProvider } from "@/lib/connectors/instances";
import { redis } from "@/lib/redis";
import { syncAssets } from "@/lib/pipeline/assets";
import { attackCoverage } from "@/lib/services/detections";
import { advanceRun, evaluateTriggers, resumeRun } from "@/lib/soar/engine";
import { decideApproval, executeResponseAction } from "@/lib/soar/response";

async function ctxFor(email: string): Promise<AccessContext> {
  const [u] = await adminDb().select().from(user).where(eq(user.email, email));
  if (!u) throw new Error(`seed user ${email} missing — run pnpm db:seed with DEMO_MODE=true`);
  return resolveAccess({ userId: u.id, name: u.name, email: u.email, isBreakGlass: u.isBreakGlass });
}

afterAll(async () => {
  await redis().quit();
});

describe("M365 demo tenant and Suspected BEC chain", () => {
  it("seeds rules, coverage, fixture telemetry, and an approval-gated response", async () => {
    const entra = connectorDef("entra");
    expect(entra?.status).toBe("available");

    const becIds = BEC_DETECTIONS.map((d) => parseSigma(d.yaml).id);
    const becRules = await adminDb().select().from(sigmaRules).where(inArray(sigmaRules.sigmaId, becIds));
    expect(becRules).toHaveLength(becIds.length);
    for (const rule of becRules) {
      const [test] = await adminDb().select().from(sigmaRuleTests).where(eq(sigmaRuleTests.ruleId, rule.id));
      expect(test?.passed, rule.title).toBe(true);
      const cases = test!.cases;
      expect(cases.some((c) => c.expect)).toBe(true);
      expect(cases.some((c) => !c.expect)).toBe(true);
    }

    const [wattle] = await adminDb().select().from(tenants).where(eq(tenants.slug, "wattle-health"));
    expect(wattle).toBeTruthy();
    const l1 = await ctxFor("l1@demo.blaksoc.local");
    const coverage = await attackCoverage(l1, [wattle!.id]);
    expect(coverage.find((c) => c.id === "T1114.003")!.rules).toBeGreaterThan(0);
    expect(coverage.find((c) => c.id === "T1528")!.rules).toBeGreaterThan(0);
    expect(coverage.find((c) => c.id === "T1621")!.rules).toBeGreaterThan(0);

    const [row] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, wattle!.id), eq(integrations.provider, "entra")));
    expect(row?.name).toBe("Microsoft 365 (demo)");
    const provider = eventProvider(row!);
    const health = await provider.health();
    const gaps = health.detail.gaps as { id: string; available: boolean }[];
    expect(gaps.find((g) => g.id === "risk_detections")!.available).toBe(false);
    expect(gaps.find((g) => g.id === "intune_devices")!.available).toBe(false);
    expect(gaps.find((g) => g.id === "signins")!.available).toBe(true);

    const since = new Date(Date.now() - 7 * 24 * 3600_000);
    const first = await provider.getAlerts({ since });
    const second = await provider.getAlerts({ since, afterCursor: first.cursor ?? undefined });
    const seen = new Set(first.alerts.map((a) => a.externalId));
    expect(second.alerts.filter((a) => seen.has(a.externalId))).toEqual([]);

    const list = await provider.getAssets();
    const scope = { tenantIds: [wattle!.id], platform: false as const };
    const once = await withScope(scope, (tx) => syncAssets(tx, wattle!.id, row!.id, list));
    const twice = await withScope(scope, (tx) => syncAssets(tx, wattle!.id, row!.id, list));
    expect([...twice.values()].sort()).toEqual([...once.values()].sort());
    const [identity] = await adminDb().select().from(assets).where(and(eq(assets.tenantId, wattle!.id), eq(assets.name, "Finance Mailbox")));
    expect(identity?.kind).toBe("identity");

    const [alert] = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, wattle!.id), eq(alerts.source, "entra"), eq(alerts.externalId, "o365:ex-rule")));
    expect(alert?.category).toBe("bec");
    expect(alert?.assetId).toBeTruthy();

    const copies = await adminDb().select().from(playbooks).where(eq(playbooks.name, "Suspected BEC"));
    expect(copies.some((p) => p.tenantId === null && p.enabled === false)).toBe(true);
    const tenantCopy = copies.find((p) => p.tenantId === wattle!.id);
    expect(tenantCopy?.enabled).toBe(false);
    await adminDb().update(playbooks).set({ enabled: true }).where(eq(playbooks.id, tenantCopy!.id));
    try {
      const manager = await ctxFor("manager@demo.blaksoc.local");
      const started = await evaluateTriggers(wattle!.id, "alert.created", { alertId: alert!.id });
      const runs = await adminDb().select().from(playbookRuns).where(eq(playbookRuns.alertId, alert!.id));
      const becRun = runs.find((r) => r.playbookId === tenantCopy!.id && started.includes(r.id));
      expect(becRun).toBeTruthy();

      let status = "RUNNING";
      for (let i = 0; i < 12 && status !== "SUCCEEDED"; i++) {
        status = (await advanceRun(wattle!.id, becRun!.id)) ?? status;
        if (status !== "WAITING_APPROVAL") continue;
        const [step] = await adminDb().select().from(playbookRunSteps).where(and(eq(playbookRunSteps.runId, becRun!.id), eq(playbookRunSteps.status, "WAITING_APPROVAL")));
        const [ap] = await adminDb().select().from(approvals).where(eq(approvals.id, step!.approvalId!));
        await decideApproval(manager, ap!.id, "APPROVED", "demo chain");
        if (ap!.kind === "response_action") {
          const executed = await executeResponseAction(wattle!.id, ap!.refId);
          expect(executed).toMatchObject({ ok: true });
        }
        await resumeRun(wattle!.id, becRun!.id, ap!.id, "APPROVED");
      }
      expect(status).toBe("SUCCEEDED");

      const [finished] = await adminDb().select().from(playbookRuns).where(eq(playbookRuns.id, becRun!.id));
      expect(finished!.incidentId).toBeTruthy();
      const tasks = await adminDb().select().from(incidentTasks).where(eq(incidentTasks.incidentId, finished!.incidentId!));
      const titles = tasks.map((task) => task.title);
      expect(titles.some((title) => /bank/i.test(title))).toBe(true);
      expect(titles.some((title) => /ReportCyber/.test(title))).toBe(true);

      const timeline = await adminDb().select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, finished!.incidentId!));
      const timelineText = timeline.map((entry) => entry.title).join("\n");
      expect(timelineText).toMatch(/awaiting approval/i);
      expect(timelineText).toMatch(/Revoke identity sessions succeeded/);
      expect(timelineText).toMatch(/Disable identity succeeded/);
      expect(timelineText).toMatch(/Remove inbox rule succeeded/);

      const audits = await adminDb().select().from(auditLog).where(eq(auditLog.tenantId, wattle!.id));
      const actions = audits.map((a) => a.action);
      expect(actions).toContain("response.request");
      expect(actions).toContain("response.execute");
    } finally {
      await adminDb().update(playbooks).set({ enabled: false }).where(eq(playbooks.id, tenantCopy!.id));
    }
  });
});
