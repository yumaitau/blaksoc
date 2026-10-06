/**
 * Live Microsoft 365 admin consent: the redirect is checked and stored, survives a re-save, and finish creates a
 * live Entra integration for the worker to poll. The Graph check is injected; nothing here calls Microsoft.
 */
process.env.M365_CONNECTOR_CLIENT_ID = "connector-app";
process.env.M365_CONNECTOR_CLIENT_SECRET = "connector-secret";

import { and, eq, gte, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { alerts, auditLog, integrations, onboardingDrafts, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { secretAad } from "@/lib/connectors/instances";
import { decryptSecret } from "@/lib/crypto";
import { signState } from "@/lib/onboarding/m365-consent";
import type { M365Consent } from "@/lib/onboarding/types";
import { finishOnboarding, getDraft, OnboardingError, recordM365Consent, saveOnboardingStep, startOnboarding } from "@/lib/services/onboarding";

const USER = "onb-live-analyst";
const AZURE = "0b6e4f00-1111-4222-8333-944445555666";
const perms = new Set<Permission>(["tenant:manage", "settings:manage", "playbook:write", "asset:write"]);
const ctx: AccessContext = {
  principal: { userId: USER, name: "Setup Analyst", email: "setup@example.invalid", isBreakGlass: false },
  isPlatform: true,
  grants: [{ roleKey: "platform_admin", tenantId: null, permissions: perms }],
  tenantIds: [],
  tenants: [],
};

const consent: M365Consent = { azureTenantId: AZURE, organisation: "River Clinic", grantedAt: "2026-10-06T00:00:00.000Z", skus: ["O365_BUSINESS_PREMIUM"] };
const granted = async (tenant: string) => ({ ...consent, azureTenantId: tenant });
const redirect = (state: string) => new URLSearchParams({ tenant: AZURE, admin_consent: "True", state });

afterAll(async () => {
  const drafts = await adminDb().select().from(onboardingDrafts).where(eq(onboardingDrafts.ownerUserId, USER));
  const ids = drafts.map((d) => d.tenantId).filter((id): id is string => !!id);
  if (ids.length) await adminDb().delete(tenants).where(inArray(tenants.id, ids));
  await adminDb().delete(onboardingDrafts).where(eq(onboardingDrafts.ownerUserId, USER));
});

describe("live Microsoft 365 consent in setup", () => {
  it("stores checked consent and finishes with a live integration", async () => {
    const started = new Date();
    const draft = await startOnboarding(ctx);
    await saveOnboardingStep(ctx, draft.id, "org", {
      name: "River Clinic Live", abn: "51 824 753 556", oricIcn: "", orgType: "accho", sectors: ["HEALTHCARE"], headcount: "12",
      locations: [{ name: "Cairns", remote: "no", link: "standard" }],
    });
    // Consent is refused before the analyst reaches the connect step.
    await expect(recordM365Consent(ctx, redirect(signState(draft.id, USER)), granted)).rejects.toMatchObject({ code: "order" });

    await saveOnboardingStep(ctx, draft.id, "contacts", {
      primaryName: "Alex", primaryChannel: "phone", primaryValue: "0412000111", afterHoursName: "Sam", afterHoursChannel: "sms",
      afterHoursValue: "0412000222", boardName: "Jo", boardChannel: "email", boardValue: "jo@example.invalid", summaryEmail: "board@example.invalid",
    });
    await saveOnboardingStep(ctx, draft.id, "stack", { identity: "m365", accounting: "Xero", itProvider: "" });

    // A forged state and a declined consent are both refused and audited.
    await expect(recordM365Consent(ctx, redirect("bad.state"), granted)).rejects.toBeInstanceOf(OnboardingError);
    const declined = new URLSearchParams({ error: "access_denied", error_description: "The admin declined", state: signState(draft.id, USER) });
    await expect(recordM365Consent(ctx, declined, granted)).rejects.toMatchObject({ code: "consent" });

    await recordM365Consent(ctx, redirect(signState(draft.id, USER)), granted);
    expect((await getDraft(ctx, draft.id)).connect?.m365Consent).toEqual(consent);

    // Re-saving the step with a different id keeps the consented tenant.
    await saveOnboardingStep(ctx, draft.id, "connect", { azureTenantId: "", domains: "" });
    const kept = await getDraft(ctx, draft.id);
    expect(kept.connect).toMatchObject({ azureTenantId: AZURE, m365Consent: consent });

    await saveOnboardingStep(ctx, draft.id, "governance", { choice: "most_protective" });
    await saveOnboardingStep(ctx, draft.id, "plan", { tier: "standard", nonprofit: "yes" });
    const done = await finishOnboarding(ctx, draft.id);

    const [entra] = await adminDb().select().from(integrations).where(and(eq(integrations.tenantId, done.tenantId), eq(integrations.provider, "entra")));
    expect(entra?.config).toEqual({ azureTenantId: AZURE, mode: "live", subscribedSkus: ["O365_BUSINESS_PREMIUM"] });
    expect(entra?.status).toBe("unknown");
    expect(JSON.parse(decryptSecret(entra!.secretCiphertext!, secretAad(entra!.id)))).toEqual({ clientId: "connector-app", clientSecret: "connector-secret" });
    // No sample alerts on a live tenant.
    expect(await adminDb().select().from(alerts).where(eq(alerts.tenantId, done.tenantId))).toHaveLength(0);

    // The audit log is append-only, so read this run's rows only.
    const actions = (await adminDb().select().from(auditLog).where(and(eq(auditLog.actorId, USER), gte(auditLog.at, started)))).map((a) => a.action);
    expect(actions).toEqual(expect.arrayContaining(["onboarding.m365_consent", "onboarding.m365_consent_failed"]));
    expect(actions.filter((a) => a === "onboarding.m365_consent_failed").length).toBe(2);
  });

  it("rejects an ABN that fails the checksum", async () => {
    const draft = await startOnboarding(ctx);
    await expect(saveOnboardingStep(ctx, draft.id, "org", {
      name: "Bad ABN", abn: "51824753557", oricIcn: "", orgType: "other", sectors: ["SMB"], headcount: "3",
      locations: [{ name: "Darwin", remote: "no", link: "standard" }],
    })).rejects.toMatchObject({ code: "abn" });
  });
});
