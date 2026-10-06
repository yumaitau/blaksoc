import { randomUUID } from "node:crypto";
import { and, desc, eq, inArray, isNull } from "drizzle-orm";
import { systemDb } from "@/db/client";
import {
  integrations, notificationDeliveries, onboardingDrafts, playbooks, reports, roles, sites, tenants,
} from "@/db/schema";
import { SECTOR_TAGS } from "@/db/schema/platform";
import { can, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { lookupAbn, normaliseAbn, validAbn } from "@/lib/onboarding/abn";
import { connectorCredentials, parseCallback, verifyConsent, verifyState } from "@/lib/onboarding/m365-consent";
import { COPY } from "@/lib/onboarding/copy";
import {
  BANDWIDTH_PROFILES, CONTACT_CHANNELS, ONBOARDING_STEPS, ORG_TYPES, REMOTE_FLAGS,
  type BandwidthProfile, type ConnectDraft, type ContactChannel, type ContactPerson, type ContactsDraft, type GovernanceDraft,
  type OnboardingStep, type OrgDraft, type OrgLocation, type OrgType, type PlanDraft, type RemoteFlag, type StackDraft,
} from "@/lib/onboarding/types";
import { encryptSecret } from "@/lib/crypto";
import { connectorDef } from "@/lib/connectors/registry";
import { eventProvider, notifier, secretAad } from "@/lib/connectors/instances";
import { SUSPECTED_BEC_PLAYBOOK } from "@/lib/detections/bec";
import { env } from "@/lib/env";
import { ingestAlert } from "@/lib/pipeline/ingest";
import { rememberDomains } from "@/lib/services/surface";
import { toPdf } from "@/lib/reports/export";
import type { ReportContent } from "@/lib/reports/types";
import { cobrandLine } from "@/lib/tenancy/brand";
import { actor, AccessDenied } from "./common";
import { createSite, createTenant } from "./admin";
import { setTenantPlan } from "./billing";
import { initialiseGovernance } from "./governance";
import { grantPartnerCustomer, partnerHome } from "./partner";
import { savePlaybook } from "./playbooks";

const ROLE_KEYS = ["customer_admin", "customer_security", "customer_readonly"] as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class OnboardingError extends Error {
  readonly code: "missing" | "order" | "slug" | "email" | "abn" | "consent";
  constructor(code: OnboardingError["code"]) {
    super(code);
    this.name = "OnboardingError";
    this.code = code;
  }
}

export type FinishResult = { tenantId: string; reportId: string; draftId: string };

/** Analyst runs setup with the customer. A partner admin can start a customer of their own. Self-serve sign-up stays closed. */
export function canRunOnboarding(ctx: AccessContext): boolean {
  return (ctx.isPlatform && can(ctx, "tenant:manage")) || partnerHome(ctx) !== null;
}

function assertAnalyst(ctx: AccessContext) {
  if (!canRunOnboarding(ctx)) throw new AccessDenied("platform tenant:manage required");
}

function text(raw: Record<string, unknown>, key: string, max: number): string {
  const value = raw[key];
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function need(value: string): string {
  if (!value) throw new OnboardingError("missing");
  return value;
}

function asStrings(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}

function parseLink(raw: string): BandwidthProfile {
  const link = raw || "standard";
  if (!BANDWIDTH_PROFILES.includes(link as BandwidthProfile)) throw new OnboardingError("missing");
  return link as BandwidthProfile;
}

function parseLocations(raw: Record<string, unknown>): OrgLocation[] {
  if (Array.isArray(raw.locations)) {
    return raw.locations.flatMap((item) => {
      if (!item || typeof item !== "object") return [];
      const rec = item as Record<string, unknown>;
      const name = text(rec, "name", 80);
      const remote = text(rec, "remote", 20);
      if (!name || !REMOTE_FLAGS.includes(remote as RemoteFlag)) return [];
      return [{ name, remote: remote as RemoteFlag, link: parseLink(text(rec, "link", 20)) }];
    });
  }
  const out: OrgLocation[] = [];
  for (let i = 1; i <= 3; i++) {
    const name = text(raw, `location_${i}`, 80);
    if (!name) continue;
    const remote = text(raw, `remote_${i}`, 20) || "no";
    if (!REMOTE_FLAGS.includes(remote as RemoteFlag)) throw new OnboardingError("missing");
    out.push({ name, remote: remote as RemoteFlag, link: parseLink(text(raw, `link_${i}`, 20)) });
  }
  return out;
}

async function parseOrg(raw: Record<string, unknown>): Promise<OrgDraft> {
  const name = need(text(raw, "name", 80));
  const abn = normaliseAbn(text(raw, "abn", 20));
  if (abn.length !== 11) throw new OnboardingError("missing");
  if (!validAbn(abn)) throw new OnboardingError("abn");
  const orgType = text(raw, "orgType", 40);
  if (!ORG_TYPES.includes(orgType as OrgType)) throw new OnboardingError("missing");
  const sectors = asStrings(raw.sectors).filter((s) => (SECTOR_TAGS as readonly string[]).includes(s));
  const indigenous = orgType === "acco" || orgType === "accho" || orgType === "pbc" || orgType === "indigenous_business";
  if (indigenous && !sectors.includes("INDIGENOUS_BUSINESS")) sectors.push("INDIGENOUS_BUSINESS");
  if (!sectors.length) throw new OnboardingError("missing");
  const headcount = Number(text(raw, "headcount", 8));
  if (!Number.isInteger(headcount) || headcount < 1 || headcount > 100_000) throw new OnboardingError("missing");
  const locations = parseLocations(raw);
  if (!locations.length) throw new OnboardingError("missing");
  const oric = text(raw, "oricIcn", 20);
  // Look the number up last, after every local check passed.
  const looked = await lookupAbn(abn, { guid: env().ABR_GUID });
  return {
    name, abn: looked.abn, abnName: looked.name, abnFound: looked.found, abnSource: looked.source, abnStatus: looked.status ?? null, oricIcn: oric || null,
    orgType: orgType as OrgType, sectors, headcount, locations,
  };
}

function parsePerson(raw: Record<string, unknown>, prefix: string): ContactPerson {
  const name = need(text(raw, `${prefix}Name`, 120));
  const channel = text(raw, `${prefix}Channel`, 20);
  if (!CONTACT_CHANNELS.includes(channel as ContactChannel)) throw new OnboardingError("missing");
  const value = need(text(raw, `${prefix}Value`, 120));
  return { name, channel: channel as ContactChannel, value };
}

function parseContacts(raw: Record<string, unknown>): ContactsDraft {
  const summaryEmail = need(text(raw, "summaryEmail", 160));
  if (!summaryEmail.includes("@") || /\s/.test(summaryEmail)) throw new OnboardingError("missing");
  return {
    primary: parsePerson(raw, "primary"),
    afterHours: parsePerson(raw, "afterHours"),
    board: parsePerson(raw, "board"),
    summaryEmail,
  };
}

function parseStack(raw: Record<string, unknown>): StackDraft {
  const identity = text(raw, "identity", 20);
  if (identity !== "m365" && identity !== "google" && identity !== "other") throw new OnboardingError("missing");
  return { identity, accounting: need(text(raw, "accounting", 120)), itProvider: text(raw, "itProvider", 120) };
}

function parseDomains(value: unknown): string[] {
  const parts = Array.isArray(value) ? value.flatMap((item) => (typeof item === "string" ? item.split(/[\s,]+/) : [])) : typeof value === "string" ? value.split(/[\s,]+/) : [];
  const domains = [...new Set(parts.map((d) => d.trim().toLowerCase()).filter(Boolean))];
  if (domains.length > 20) throw new OnboardingError("missing");
  for (const domain of domains) {
    if (domain.length > 253 || !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new OnboardingError("missing");
  }
  return domains;
}

/** A recorded admin consent survives a re-save of the step and fixes the tenant id. */
function parseConnect(raw: Record<string, unknown>, prior: ConnectDraft | null): ConnectDraft {
  const azure = text(raw, "azureTenantId", 40);
  if (azure && !UUID.test(azure)) throw new OnboardingError("missing");
  const consent = prior?.m365Consent ?? null;
  return { azureTenantId: consent?.azureTenantId ?? (azure || null), m365Consent: consent, domains: parseDomains(raw.domains), agents: "later" };
}

function parseGovernance(raw: Record<string, unknown>): GovernanceDraft {
  if (text(raw, "choice", 40) !== "most_protective") throw new OnboardingError("missing");
  return { choice: "most_protective" };
}

function parsePlan(raw: Record<string, unknown>): PlanDraft {
  const tier = text(raw, "tier", 20);
  if (tier !== "essentials" && tier !== "standard" && tier !== "plus") throw new OnboardingError("missing");
  const flag = raw.nonprofit;
  return { tier, nonprofit: flag === true || flag === "yes" };
}

async function parseStep(step: OnboardingStep, raw: Record<string, unknown>, row: typeof onboardingDrafts.$inferSelect) {
  if (step === "org") return { org: await parseOrg(raw) };
  if (step === "contacts") return { contacts: parseContacts(raw) };
  if (step === "stack") return { stack: parseStack(raw) };
  if (step === "connect") return { connect: parseConnect(raw, row.connect) };
  if (step === "governance") return { governance: parseGovernance(raw) };
  return { plan: parsePlan(raw) };
}

function slugFor(name: string): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 34).replace(/-+$/g, "");
  const suffix = randomUUID().replace(/-/g, "").slice(0, 4);
  return `${base || "org"}-${suffix}`.slice(0, 40);
}

function withTenant(ctx: AccessContext, tenant: { id: string; slug: string; name: string; kind: "mssp" | "partner" | "customer"; parentId?: string | null; brandName?: string | null }): AccessContext {
  if (ctx.tenantIds.includes(tenant.id)) return ctx;
  return {
    ...ctx,
    tenantIds: [...ctx.tenantIds, tenant.id],
    tenants: [...ctx.tenants, { id: tenant.id, slug: tenant.slug, name: tenant.name, kind: tenant.kind, parentId: tenant.parentId ?? null, brandName: tenant.brandName ?? null, cobrand: null }],
  };
}

export async function startOnboarding(ctx: AccessContext) {
  assertAnalyst(ctx);
  const [open] = await systemDb()
    .select()
    .from(onboardingDrafts)
    .where(and(eq(onboardingDrafts.ownerUserId, ctx.principal.userId), eq(onboardingDrafts.status, "draft")));
  if (open) return open;
  return systemDb().transaction(async (tx) => {
    const [row] = await tx.insert(onboardingDrafts).values({ ownerUserId: ctx.principal.userId, status: "draft", step: "org" }).returning();
    await audit(tx, { ...actor(ctx), tenantId: null, action: "onboarding.save", targetType: "onboarding_draft", targetId: row!.id, detail: { step: "start" } });
    return row!;
  });
}

export async function getDraft(ctx: AccessContext, draftId: string) {
  assertAnalyst(ctx);
  const [row] = await systemDb().select().from(onboardingDrafts).where(eq(onboardingDrafts.id, draftId));
  if (!row || row.ownerUserId !== ctx.principal.userId) throw new AccessDenied("draft");
  return row;
}

export async function ownDraft(ctx: AccessContext) {
  assertAnalyst(ctx);
  const [row] = await systemDb()
    .select()
    .from(onboardingDrafts)
    .where(eq(onboardingDrafts.ownerUserId, ctx.principal.userId))
    .orderBy(desc(onboardingDrafts.updatedAt))
    .limit(1);
  return row ?? null;
}

export async function saveOnboardingStep(ctx: AccessContext, draftId: string, step: OnboardingStep, raw: Record<string, unknown>) {
  assertAnalyst(ctx);
  if (!ONBOARDING_STEPS.includes(step)) throw new OnboardingError("missing");
  // Parse outside the transaction: the org step calls the business register.
  const pre = await getDraft(ctx, draftId);
  if (pre.status === "complete") return pre;
  const patch = await parseStep(step, raw, pre);
  return systemDb().transaction(async (tx) => {
    const [row] = await tx.select().from(onboardingDrafts).where(eq(onboardingDrafts.id, draftId)).for("update");
    if (!row || row.ownerUserId !== ctx.principal.userId) throw new AccessDenied("draft");
    if (row.status === "complete") return row;
    const current = ONBOARDING_STEPS.indexOf(row.step as OnboardingStep);
    const saving = ONBOARDING_STEPS.indexOf(step);
    if (current < 0 || saving > current) throw new OnboardingError("order");
    if (patch.connect && row.connect?.m365Consent) {
      patch.connect.m365Consent = row.connect.m365Consent;
      patch.connect.azureTenantId = row.connect.m365Consent.azureTenantId;
    }
    const next = ONBOARDING_STEPS[Math.max(current, Math.min(ONBOARDING_STEPS.length - 1, saving + 1))]!;
    const [saved] = await tx.update(onboardingDrafts).set({ ...patch, step: next, updatedAt: new Date() }).where(eq(onboardingDrafts.id, draftId)).returning();
    await audit(tx, { ...actor(ctx), tenantId: row.tenantId, action: "onboarding.save", targetType: "onboarding_draft", targetId: draftId, detail: { step } });
    if (step === "org" && patch.org) {
      await audit(tx, { ...actor(ctx), tenantId: row.tenantId, action: "onboarding.abn_lookup", targetType: "onboarding_draft", targetId: draftId, detail: { found: patch.org.abnFound, source: patch.org.abnSource } });
    }
    return saved!;
  });
}

/**
 * Handles the admin-consent redirect. The state must be this analyst's, for an open draft past the stack step.
 * Consent is stored only after a Graph call with it succeeds. Failures are audited too.
 */
export async function recordM365Consent(ctx: AccessContext, query: URLSearchParams, check: typeof verifyConsent = verifyConsent) {
  assertAnalyst(ctx);
  let draftId = "";
  try {
    const state = verifyState(query.get("state") ?? "", ctx.principal.userId);
    draftId = state.draftId;
    const row = await getDraft(ctx, draftId);
    if (row.status === "complete" || ONBOARDING_STEPS.indexOf(row.step as OnboardingStep) < ONBOARDING_STEPS.indexOf("connect")) throw new OnboardingError("order");
    const { azureTenantId } = parseCallback(query);
    const consent = await check(azureTenantId);
    return await systemDb().transaction(async (tx) => {
      const [fresh] = await tx.select().from(onboardingDrafts).where(eq(onboardingDrafts.id, draftId)).for("update");
      const connect: ConnectDraft = { domains: [], agents: "later", ...fresh!.connect, azureTenantId: consent.azureTenantId, m365Consent: consent };
      const [saved] = await tx.update(onboardingDrafts).set({ connect, updatedAt: new Date() }).where(eq(onboardingDrafts.id, draftId)).returning();
      await audit(tx, { ...actor(ctx), tenantId: fresh!.tenantId, action: "onboarding.m365_consent", targetType: "onboarding_draft", targetId: draftId, detail: { azureTenantId: consent.azureTenantId, organisation: consent.organisation, skus: consent.skus.length } });
      return saved!;
    });
  } catch (err) {
    if (err instanceof AccessDenied || (err instanceof OnboardingError && err.code === "order")) throw err;
    await systemDb().transaction((tx) =>
      audit(tx, { ...actor(ctx), tenantId: null, action: "onboarding.m365_consent_failed", targetType: "onboarding_draft", targetId: draftId || undefined, detail: { reason: err instanceof Error ? err.message.slice(0, 200) : "failed" } }));
    throw new OnboardingError("consent");
  }
}

async function openPartnerTenant(ctx: AccessContext, partnerId: string, name: string, sectors: string[]) {
  let last: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return await grantPartnerCustomer(ctx, partnerId, { name, slug: slugFor(name), sectors, deploymentMode: "shared" });
    } catch (err) {
      if (err instanceof AccessDenied) throw err;
      if (err instanceof Error && err.message.includes("slug must be")) throw new OnboardingError("slug");
      last = err;
    }
  }
  throw last;
}

async function openTenant(ctx: AccessContext, name: string, sectors: string[]) {
  let last: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return await createTenant(ctx, { name, slug: slugFor(name), sectors, deploymentMode: "shared" });
    } catch (err) {
      if (err instanceof AccessDenied) throw err;
      if (err instanceof Error && err.message.includes("slug must be")) throw new OnboardingError("slug");
      last = err;
    }
  }
  throw last;
}

async function ensureSites(ctx: AccessContext, tenantId: string, locations: OrgLocation[]) {
  const existing = await systemDb().select({ id: sites.id }).from(sites).where(eq(sites.tenantId, tenantId));
  if (existing.length) return;
  for (const loc of locations) {
    const location = loc.remote === "no" ? loc.name : `${loc.name}, ${loc.remote}`;
    await createSite(ctx, tenantId, loc.name, location, loc.link ?? "standard");
  }
}

/**
 * With admin consent, the integration is live and uses the connector app. The worker's 30-second poll
 * reads it first, so a slow or failing Graph call never blocks setup.
 * Without consent, sample data is recorded so the customer sees a first alert.
 */
async function recordM365(tenantId: string, connect: ConnectDraft) {
  const consent = connect.m365Consent ?? null;
  let [row] = await systemDb().select().from(integrations).where(and(eq(integrations.tenantId, tenantId), eq(integrations.provider, "entra")));
  if (!row) {
    const entra = connectorDef("entra");
    const id = randomUUID();
    [row] = await systemDb().insert(integrations).values({
      id,
      tenantId,
      category: "identity",
      provider: "entra",
      name: "Microsoft 365",
      config: consent
        ? { azureTenantId: consent.azureTenantId, mode: "live", subscribedSkus: consent.skus }
        : { azureTenantId: connect.azureTenantId ?? randomUUID(), mode: "fixture", subscribedSkus: ["O365_BUSINESS_ESSENTIALS"] },
      secretCiphertext: consent ? encryptSecret(JSON.stringify(connectorCredentials()), secretAad(id)) : null,
      status: consent ? "unknown" : "healthy",
      permissions: entra?.remotePermissions ?? [],
    }).returning();
  }
  if (consent) return;
  const { alerts: list } = await eventProvider(row!).getAlerts({ since: new Date(Date.now() - 7 * 24 * 3600_000) });
  for (const alert of list) await ingestAlert({ tenantId, integrationId: row!.id, source: "entra", alert, intel: null });
}

async function ensurePlaybooks(ctx: AccessContext, tenantId: string) {
  const existing = await systemDb().select({ id: playbooks.id }).from(playbooks).where(eq(playbooks.tenantId, tenantId));
  if (existing.length) return;
  const globals = await systemDb().select().from(playbooks).where(isNull(playbooks.tenantId));
  const sources = globals.map((g) => ({ tenantId, name: g.name, description: g.description, trigger: g.trigger, steps: g.steps }));
  if (!sources.some((s) => s.name === SUSPECTED_BEC_PLAYBOOK.name)) {
    sources.push({
      tenantId,
      name: SUSPECTED_BEC_PLAYBOOK.name,
      description: SUSPECTED_BEC_PLAYBOOK.description,
      trigger: SUSPECTED_BEC_PLAYBOOK.trigger,
      steps: [...SUSPECTED_BEC_PLAYBOOK.steps],
    });
  }
  for (const input of sources) await savePlaybook(ctx, input);
}

function connectedLine(identity: StackDraft["identity"], live = false): string {
  if (identity === "m365") return live ? COPY.connectedM365Live : COPY.connectedM365;
  if (identity === "google") return COPY.connectedGoogle;
  return COPY.connectedOther;
}

function domainLine(domains: string[]): string {
  return domains.length ? `${COPY.domainsLater} ${domains.join(", ")}.` : COPY.domainsNone;
}

function welcomeContent(tenantName: string, stack: StackDraft, connect: ConnectDraft, now: Date, cobrand: string | null): ReportContent {
  return {
    tenantName,
    generatedAt: now.toISOString(),
    period: { start: now.toISOString(), end: now.toISOString() },
    ...(cobrand ? { cobrand } : {}),
    sections: [
      { heading: COPY.reportConnected, basis: "observed", author: "system", body: connectedLine(stack.identity, !!connect.m365Consent) },
      { heading: COPY.reportWhy, basis: "observed", author: "system", body: COPY.reportWhyBody },
      { heading: COPY.reportDomains, basis: "observed", author: "system", body: domainLine(connect.domains) },
      { heading: COPY.reportRules, basis: "observed", author: "system", body: COPY.govLead },
      { heading: COPY.reportSensors, basis: "observed", author: "system", body: COPY.agents },
    ],
  };
}

async function sendSummary(tenant: { id: string; name: string }, to: string, summary: string) {
  let [row] = await systemDb()
    .select()
    .from(integrations)
    .where(and(eq(integrations.tenantId, tenant.id), eq(integrations.provider, "email"), eq(integrations.name, "Setup summary email")));
  if (!row) {
    const id = randomUUID();
    [row] = await systemDb().insert(integrations).values({
      id,
      tenantId: tenant.id,
      category: "collaboration",
      provider: "email",
      name: "Setup summary email",
      config: { host: "fixture.invalid", port: 587, from: "setup@example.com", mode: "fixture" },
      secretCiphertext: encryptSecret(JSON.stringify({ username: "fixture", password: "fixture-key" }), secretAad(id)),
      status: "healthy",
    }).returning();
  }
  const n = notifier(row!);
  if (!n) throw new OnboardingError("email");
  const receipt = await n.deliver({
    event: "onboarding.summary",
    tenant: { id: tenant.id, name: tenant.name },
    title: COPY.emailTitle,
    url: `${env().APP_URL}/portal`,
    summary,
    to,
  });
  if (receipt.status !== "sent") throw new OnboardingError("email");
  return receipt;
}

export async function finishOnboarding(ctx: AccessContext, draftId: string, opts?: { partnerConsent?: boolean }): Promise<FinishResult> {
  assertAnalyst(ctx);
  const row = await getDraft(ctx, draftId);
  if (row.status === "complete" && row.tenantId) {
    const [report] = await systemDb().select().from(reports).where(and(eq(reports.tenantId, row.tenantId), eq(reports.kind, "welcome")));
    return { tenantId: row.tenantId, reportId: report?.id ?? "", draftId: row.id };
  }
  if (!row.org || !row.contacts || !row.stack || !row.connect || !row.governance || !row.plan) throw new OnboardingError("missing");

  const partnerId = partnerHome(ctx);
  let tenant = row.tenantId ? (await systemDb().select().from(tenants).where(eq(tenants.id, row.tenantId)))[0] : undefined;
  if (!tenant) {
    if (partnerId) {
      if (!opts?.partnerConsent) throw new OnboardingError("missing");
      tenant = await openPartnerTenant(ctx, partnerId, row.org.name, row.org.sectors);
    } else {
      tenant = await openTenant(ctx, row.org.name, row.org.sectors);
    }
    await systemDb().update(onboardingDrafts).set({ tenantId: tenant.id, updatedAt: new Date() }).where(eq(onboardingDrafts.id, row.id));
  }
  const wide = withTenant(ctx, tenant);
  await ensureSites(wide, tenant.id, row.org.locations);
  if (row.stack.identity === "m365") await recordM365(tenant.id, row.connect);
  await setTenantPlan(wide, tenant.id, { tier: row.plan.tier, nonprofit: row.plan.nonprofit });
  await ensurePlaybooks(wide, tenant.id);

  const roleRows = await systemDb().select({ key: roles.key }).from(roles).where(inArray(roles.key, [...ROLE_KEYS]));
  if (roleRows.length !== ROLE_KEYS.length) throw new Error("default roles missing");

  const now = new Date();
  const partner = partnerId ? ctx.tenants.find((t) => t.id === partnerId) : undefined;
  const content = welcomeContent(tenant.name, row.stack, row.connect, now, partner ? cobrandLine(partner.name, partner.brandName) : null);
  await toPdf(COPY.emailTitle, content);
  let [report] = await systemDb().select().from(reports).where(and(eq(reports.tenantId, tenant.id), eq(reports.kind, "welcome")));
  if (!report) {
    [report] = await systemDb().insert(reports).values({
      tenantId: tenant.id,
      kind: "welcome",
      title: COPY.emailTitle,
      periodStart: now,
      periodEnd: now,
      status: "ready",
      content,
      generatedBy: ctx.principal.userId,
    }).returning();
  }

  const summary = [connectedLine(row.stack.identity, !!row.connect.m365Consent), COPY.reportWhyBody, domainLine(row.connect.domains), COPY.govLead, COPY.agents].join(" ");
  const [alreadySent] = await systemDb()
    .select()
    .from(notificationDeliveries)
    .where(and(
      eq(notificationDeliveries.tenantId, tenant.id),
      eq(notificationDeliveries.channel, "email"),
      eq(notificationDeliveries.destination, row.contacts.summaryEmail),
      eq(notificationDeliveries.status, "sent"),
    ));
  const receipt = alreadySent ? { providerRef: alreadySent.providerRef } : await sendSummary(tenant, row.contacts.summaryEmail, summary);

  await systemDb().transaction(async (tx) => {
    if (!alreadySent) {
      await tx.insert(notificationDeliveries).values({
        tenantId: tenant.id,
        provider: "email",
        channel: "email",
        destination: row.contacts!.summaryEmail,
        status: "sent",
        providerRef: receipt.providerRef,
        detail: { reportId: report!.id },
      });
    }
    const who = actor(ctx);
    await rememberDomains(tx, who, tenant.id, row.connect!.domains, "onboarding");
    await audit(tx, { ...who, tenantId: tenant.id, action: "onboarding.roles", targetType: "tenant", targetId: tenant.id, detail: { keys: [...ROLE_KEYS] } });
    await initialiseGovernance(tx, tenant.id, who);
    await audit(tx, { ...who, tenantId: tenant.id, action: "onboarding.governance", targetType: "tenant", targetId: tenant.id, detail: { choice: "most_protective", enforced: true } });
    await audit(tx, { ...who, tenantId: tenant.id, action: "onboarding.summary", targetType: "report", targetId: report!.id, detail: { reportId: report!.id, providerRef: receipt.providerRef } });
    await audit(tx, { ...who, tenantId: tenant.id, action: "onboarding.finish", targetType: "tenant", targetId: tenant.id, detail: { draftId: row.id } });
    await tx.update(onboardingDrafts).set({ status: "complete", step: "plan", tenantId: tenant.id, updatedAt: new Date() }).where(eq(onboardingDrafts.id, row.id));
  });

  return { tenantId: tenant.id, reportId: report!.id, draftId: row.id };
}
