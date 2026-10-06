/**
 * Analyst setup: saved steps, a first Microsoft 365 alert, a welcome PDF, and a fixture summary email.
 * The test calls finishOnboarding only for the alert path. It does not ingest alerts itself.
 */
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, auditLog, dataGovernance, integrations, monitoredDomains, notificationDeliveries, onboardingDrafts, playbooks, reports, sites, tenantPlans, tenants } from "@/db/schema";
import { withScope } from "@/db/scope";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { toPdf } from "@/lib/reports/export";
import { finishOnboarding, getDraft, OnboardingError, saveOnboardingStep, startOnboarding } from "@/lib/services/onboarding";

const USER = "onb-analyst";
const RESUME = "onb-resume";
const GOOGLE = "onb-google";
const OTHER = "onb-other";
const perms = new Set<Permission>(["tenant:manage", "settings:manage", "playbook:write", "asset:write"]);

function analyst(userId: string): AccessContext {
  return {
    principal: { userId, name: "Setup Analyst", email: "setup@example.invalid", isBreakGlass: false },
    isPlatform: true,
    grants: [{ roleKey: "platform_admin", tenantId: null, permissions: perms }],
    tenantIds: [],
    tenants: [],
  };
}

const org = {
  name: "River Clinic",
  abn: "51824753556",
  oricIcn: "",
  orgType: "accho",
  sectors: ["HEALTHCARE"],
  headcount: "12",
  locations: [{ name: "Townsville", remote: "remote", link: "low" }],
};

const contacts = {
  primaryName: "Alex Reed",
  primaryChannel: "phone",
  primaryValue: "0412000111",
  afterHoursName: "Sam Lee",
  afterHoursChannel: "sms",
  afterHoursValue: "0412000222",
  boardName: "Jo King",
  boardChannel: "email",
  boardValue: "jo@example.invalid",
  summaryEmail: "board@example.invalid",
};

async function fill(ctx: AccessContext, draftId: string, identity: "m365" | "google") {
  await saveOnboardingStep(ctx, draftId, "org", org);
  await saveOnboardingStep(ctx, draftId, "contacts", contacts);
  await saveOnboardingStep(ctx, draftId, "stack", { identity, accounting: "Xero", itProvider: "" });
  await saveOnboardingStep(ctx, draftId, "connect", { azureTenantId: "", domains: ["river.example"] });
  await saveOnboardingStep(ctx, draftId, "governance", { choice: "most_protective" });
  await saveOnboardingStep(ctx, draftId, "plan", { tier: "standard", nonprofit: "yes" });
}

afterAll(async () => {
  const drafts = await adminDb().select().from(onboardingDrafts).where(inArray(onboardingDrafts.ownerUserId, [USER, RESUME, GOOGLE, OTHER]));
  const tenantIds = drafts.map((d) => d.tenantId).filter((id): id is string => !!id);
  if (tenantIds.length) await adminDb().delete(tenants).where(inArray(tenants.id, tenantIds));
  await adminDb().delete(onboardingDrafts).where(inArray(onboardingDrafts.ownerUserId, [USER, RESUME, GOOGLE, OTHER]));
});

describe("onboarding wizard", () => {
  it("finishes a new group through a first Microsoft 365 alert", async () => {
    const ctx = analyst(USER);
    const draft = await startOnboarding(ctx);
    await fill(ctx, draft.id, "m365");
    const done = await finishOnboarding(ctx, draft.id);
    const again = await finishOnboarding(ctx, draft.id);
    expect(again.tenantId).toBe(done.tenantId);

    const entraAlerts = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, done.tenantId), eq(alerts.source, "entra")));
    expect(entraAlerts.length).toBeGreaterThan(0);

    const books = await adminDb().select().from(playbooks).where(eq(playbooks.tenantId, done.tenantId));
    expect(books.length).toBeGreaterThan(0);
    expect(books.every((b) => b.enabled === false)).toBe(true);
    expect(books.some((b) => b.name === "Suspected BEC")).toBe(true);

    const [report] = await adminDb().select().from(reports).where(eq(reports.id, done.reportId));
    expect(report?.kind).toBe("welcome");
    expect(report?.content.sections.some((s) => s.body?.includes("sample Microsoft 365"))).toBe(true);
    expect(report?.content.sections.some((s) => s.body?.includes("strongest data rules are on"))).toBe(true);
    const pdf = await toPdf(report!.title, report!.content);
    expect(Buffer.from(pdf.subarray(0, 4)).toString("latin1")).toBe("%PDF");

    const [mail] = await adminDb().select().from(notificationDeliveries).where(and(eq(notificationDeliveries.tenantId, done.tenantId), eq(notificationDeliveries.channel, "email")));
    expect(mail).toMatchObject({ status: "sent", destination: "board@example.invalid", providerRef: "fixture-email" });

    const [plan] = await adminDb().select().from(tenantPlans).where(eq(tenantPlans.tenantId, done.tenantId));
    expect(plan).toMatchObject({ tier: "standard", nonprofit: true });

    const [site] = await adminDb().select().from(sites).where(eq(sites.tenantId, done.tenantId));
    expect(site?.location).toContain("remote");
    expect(site?.bandwidthProfile).toBe("low");

    const [tenant] = await adminDb().select().from(tenants).where(eq(tenants.id, done.tenantId));
    expect(tenant?.sectors).toContain("INDIGENOUS_BUSINESS");
    expect(tenant?.settings.ai.enabled).toBe(true);
    // The setting alone is not enough: the governance profile written at finish keeps AI off and data in Australia.
    const [gov] = await adminDb().select().from(dataGovernance).where(eq(dataGovernance.tenantId, done.tenantId));
    expect(gov?.profile).toEqual({ residencyLock: true, sightings: null, ai: { assistant: false, triage_summary: false } });

    const [entra] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, done.tenantId), eq(integrations.provider, "entra")));
    expect(entra?.config).toMatchObject({ mode: "fixture" });
    const [watched] = await adminDb().select().from(monitoredDomains).where(eq(monitoredDomains.tenantId, done.tenantId));
    expect(watched).toMatchObject({ name: "river.example", source: "onboarding" });

    const audits = (await adminDb().select().from(auditLog).where(eq(auditLog.actorId, USER))).filter((a) => a.tenantId === done.tenantId || a.targetId === done.tenantId || a.targetId === draft.id);
    const actions = new Set(audits.map((a) => a.action));
    for (const action of ["onboarding.save", "onboarding.abn_lookup", "tenant.create", "plan.update", "playbook.create", "onboarding.roles", "onboarding.governance", "onboarding.summary", "onboarding.finish"]) {
      expect(actions.has(action)).toBe(true);
    }
    expect(audits.find((a) => a.action === "tenant.create" && a.targetId === done.tenantId)).toMatchObject({ tenantId: null, targetId: done.tenantId });
    expect(audits.find((a) => a.action === "onboarding.abn_lookup")?.detail).toMatchObject({ found: true });
    expect(audits.find((a) => a.action === "onboarding.roles")?.detail).toMatchObject({ keys: ["customer_admin", "customer_security", "customer_readonly"] });
    expect(audits.find((a) => a.action === "onboarding.governance")?.detail).toMatchObject({ choice: "most_protective", enforced: true });
    expect(audits.find((a) => a.action === "onboarding.summary")?.detail).toMatchObject({ reportId: done.reportId, providerRef: "fixture-email" });

    const saved = await getDraft(ctx, draft.id);
    expect(saved.status).toBe("complete");
    expect(saved.org?.name).toBe("River Clinic");
  });

  it("keeps an unfinished draft and refuses another analyst", async () => {
    const ctx = analyst(RESUME);
    const other = analyst(OTHER);
    const draft = await startOnboarding(ctx);
    await saveOnboardingStep(ctx, draft.id, "org", { ...org, name: "Paused Group" });
    const saved = await getDraft(ctx, draft.id);
    expect(saved.step).toBe("contacts");
    expect(saved.org?.abnFound).toBe(true);
    await expect(finishOnboarding(ctx, draft.id)).rejects.toBeInstanceOf(OnboardingError);
    await expect(getDraft(other, draft.id)).rejects.toBeInstanceOf(AccessDenied);
  });

  it("records Google without an Entra connection", async () => {
    const ctx = analyst(GOOGLE);
    const draft = await startOnboarding(ctx);
    await fill(ctx, draft.id, "google");
    const done = await finishOnboarding(ctx, draft.id);
    const entra = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, done.tenantId), eq(integrations.provider, "entra")));
    expect(entra).toHaveLength(0);
    const entraAlerts = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, done.tenantId), eq(alerts.source, "entra")));
    expect(entraAlerts).toHaveLength(0);
    const [report] = await adminDb().select().from(reports).where(eq(reports.id, done.reportId));
    expect(report?.content.sections.some((s) => s.body?.includes("did not connect"))).toBe(true);
  });

  it("hides drafts from the app role", async () => {
    const rows = await withScope({ tenantIds: [], platform: true }, (tx) => tx.select().from(onboardingDrafts));
    expect(rows).toEqual([]);
  });
});
