import { and, desc, eq, inArray, isNull, or, sql } from "drizzle-orm";
import { systemDb, db } from "@/db/client";
import { advisories, alerts, assets, intelFeeds, intelMatches, intelTags, SECTOR_TAGS, sigmaRules, tenantFeedEntitlements, tenants, vulnerabilities, type SectorTag } from "@/db/schema";
import { withScope } from "@/db/scope";
import { assertCan, can, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { intelProviderFor } from "@/lib/connectors/instances";
import { checkGovernedSighting } from "@/lib/governance/policy";
import { emptyProfile, relevanceMatcher, type AdvisoryText, type EstateProfile, type Relevance } from "@/lib/intel/relevance";
import { actor, AccessDenied, scoped } from "./common";
import { governanceProfile } from "./governance";

/** Live search across OpenCTI (the CTI system of record) plus local sector tags. */
export async function searchIntel(ctx: AccessContext, term: string, types?: string[]) {
  assertCan(ctx, "intel:read");
  const intel = await intelProviderFor(systemDb(), null);
  if (!intel) return { configured: false as const, results: [] };
  const results = await intel.provider.search(term, types);
  const tags = results.length ? await db().select().from(intelTags).where(inArray(intelTags.openctiId, results.map((r) => r.id))) : [];
  const byId = new Map(tags.map((t) => [t.openctiId, t.tags]));
  return { configured: true as const, provider: intel.provider.kind, results: results.map((r) => ({ ...r, sectorTags: byId.get(r.id) ?? [] })) };
}

/** Tag an OpenCTI object with Australian sector relevance; mirrored to OpenCTI labels. */
export async function tagIntel(ctx: AccessContext, input: { openctiId: string; entityType: string; name: string; tags: SectorTag[] }) {
  assertCan(ctx, "intel:write");
  if (!ctx.isPlatform) throw new AccessDenied("intel tagging is a SOC function");
  const tags = input.tags.filter((t) => (SECTOR_TAGS as readonly string[]).includes(t));
  await db()
    .insert(intelTags)
    .values({ openctiId: input.openctiId, entityType: input.entityType, name: input.name, tags, updatedBy: ctx.principal.userId })
    .onConflictDoUpdate({ target: intelTags.openctiId, set: { tags, updatedBy: ctx.principal.userId, updatedAt: new Date() } });
  const intel = await intelProviderFor(systemDb(), null);
  await intel?.provider.addLabels(input.openctiId, tags.map((t) => t.toLowerCase())).catch(() => undefined);
  await withScope({ tenantIds: [], platform: true }, (tx) => audit(tx, { ...actor(ctx), tenantId: null, action: "intel.tag", targetType: "opencti", targetId: input.openctiId, detail: { tags } }));
  return tags;
}

export async function listTagged(ctx: AccessContext, tag?: SectorTag) {
  assertCan(ctx, "intel:read");
  return db().select().from(intelTags).where(tag ? sql`${tag} = any(${intelTags.tags})` : undefined).orderBy(desc(intelTags.updatedAt)).limit(200);
}

export async function listAdvisories(ctx: AccessContext, opts: { source?: string; since?: Date; limit?: number } = {}) {
  if (!ctx.tenantIds.length) throw new AccessDenied();
  const where = and(opts.source ? eq(advisories.source, opts.source) : undefined, opts.since ? sql`${advisories.publishedAt} >= ${opts.since.toISOString()}::timestamptz` : undefined);
  return db().select().from(advisories).where(where).orderBy(desc(advisories.publishedAt)).limit(opts.limit ?? 50);
}

/** Techniques named by enabled Sigma rules the caller can see. */
export async function coveredAttackTechniques(ctx: AccessContext): Promise<string[]> {
  const rows = await scoped(ctx, "detection:read", (tx, scopeTenants) =>
    tx
      .select({ techniques: sigmaRules.attackTechniques })
      .from(sigmaRules)
      .where(and(eq(sigmaRules.enabled, true), or(isNull(sigmaRules.tenantId), scopeTenants.length ? inArray(sigmaRules.tenantId, scopeTenants) : sql`false`))),
  );
  return [...new Set(rows.flatMap((row) => row.techniques))];
}

/** Advisories scored for relevance, newest first: about two years of ACSC and CISA output. */
export const RELEVANCE_SCAN = 1000;

/** Days of alerts whose techniques count as seen in an estate. */
export const TECHNIQUE_WINDOW_DAYS = 30;

/**
 * What an estate runs and what attacks it actually sees: open CVEs, installed software and operating systems per
 * asset, and techniques on active-lane alerts in the window. Passive (Hermes- or analyst-tuned noise) and
 * false-positive alerts do not count. Techniques need alert:read; without it they are left out.
 */
export async function estateProfile(ctx: AccessContext, tenantIds?: readonly string[], now = new Date()): Promise<EstateProfile> {
  const profile = emptyProfile();
  await scoped(
    ctx,
    "asset:read",
    async (tx, ids) => {
      const [cves, software, os] = await Promise.all([
        tx.select({ cve: vulnerabilities.cve, n: sql<number>`count(distinct ${vulnerabilities.assetId})::int` }).from(vulnerabilities).where(and(inArray(vulnerabilities.tenantId, ids), eq(vulnerabilities.status, "open"))).groupBy(vulnerabilities.cve),
        tx
          .select({ name: sql<string>`s.pkg->>'name'`, n: sql<number>`count(distinct ${assets.id})::int` })
          .from(assets)
          .innerJoin(sql`lateral jsonb_array_elements(${assets.software}) as s(pkg)`, sql`true`)
          .where(inArray(assets.tenantId, ids))
          .groupBy(sql`1`),
        tx.select({ os: assets.os, n: sql<number>`count(*)::int` }).from(assets).where(and(inArray(assets.tenantId, ids), sql`${assets.os} is not null`)).groupBy(assets.os),
      ]);
      for (const r of cves) profile.cves.set(r.cve, r.n);
      for (const r of software) if (r.name) profile.software.set(r.name, r.n);
      for (const r of os) profile.os.set(r.os!, r.n);
    },
    tenantIds,
  );
  if (!can(ctx, "alert:read")) return profile;
  const since = new Date(now.getTime() - TECHNIQUE_WINDOW_DAYS * 86_400_000);
  await scoped(
    ctx,
    "alert:read",
    async (tx, ids) => {
      const rows = await tx
        .select({ t: sql<string>`unnest(${alerts.attackTechniques})`.as("t"), n: sql<number>`count(*)::int` })
        .from(alerts)
        .where(and(inArray(alerts.tenantId, ids), eq(alerts.lane, "active"), sql`${alerts.status} <> 'FALSE_POSITIVE'`, sql`${alerts.occurredAt} >= ${since.toISOString()}::timestamptz`))
        .groupBy(sql`1`);
      for (const r of rows) profile.techniques.set(r.t, r.n);
    },
    tenantIds,
  ).catch((e) => {
    if (!(e instanceof AccessDenied)) throw e;
  });
  return profile;
}

/** Score advisories against the caller's estate, keeping input order. */
export async function withRelevance<A extends AdvisoryText>(ctx: AccessContext, rows: A[], tenantIds?: readonly string[]): Promise<(A & { relevance: Relevance })[]> {
  if (!rows.length) return [];
  const match = relevanceMatcher(await estateProfile(ctx, tenantIds));
  return rows.map((a) => ({ ...a, relevance: match(a) }));
}

/** Advisories relevant to a tenant: tag overlap with its sectors, or CVEs present in its estate. */
export async function advisoriesForTenant(ctx: AccessContext, tenantId: string) {
  assertCan(ctx, "portal:read", tenantId);
  return withScope({ tenantIds: [tenantId], platform: false }, async (tx) => {
    const [t] = await tx.select({ sectors: tenants.sectors }).from(tenants).where(eq(tenants.id, tenantId));
    const sectors = t?.sectors ?? [];
    return tx
      .select()
      .from(advisories)
      .where(sql`${advisories.tags} && string_to_array(${["AUSTRALIA", ...sectors].join(",")}, ',')
        or exists (select 1 from vulnerabilities v where v.tenant_id = ${tenantId} and v.status = 'open' and v.cve = any(${advisories.cves}))`)
      .orderBy(desc(advisories.publishedAt))
      .limit(20);
  });
}

export async function listFeeds(ctx: AccessContext) {
  assertCan(ctx, "intel:read");
  const feeds = await db().select().from(intelFeeds).orderBy(intelFeeds.category, intelFeeds.name);
  const ents = ctx.isPlatform ? await withScope({ tenantIds: ctx.tenantIds, platform: true }, (tx) => tx.select().from(tenantFeedEntitlements)) : [];
  return feeds.map((f) => ({ ...f, entitledTenants: ents.filter((e) => e.feedKey === f.key && e.allowed).map((e) => e.tenantId) }));
}

export async function setFeedEnabled(ctx: AccessContext, key: string, enabled: boolean) {
  if (!ctx.isPlatform || !can(ctx, "settings:manage")) throw new AccessDenied();
  await db().update(intelFeeds).set({ enabled }).where(eq(intelFeeds.key, key));
  await withScope({ tenantIds: [], platform: true }, (tx) => audit(tx, { ...actor(ctx), tenantId: null, action: "intel.feed_toggle", targetType: "intel_feed", targetId: key, detail: { enabled } }));
}

export async function setFeedEntitlement(ctx: AccessContext, key: string, tenantId: string, allowed: boolean) {
  if (!ctx.isPlatform || !can(ctx, "settings:manage")) throw new AccessDenied();
  await withScope({ tenantIds: [tenantId], platform: true }, async (tx) => {
    await tx.insert(tenantFeedEntitlements).values({ tenantId, feedKey: key, allowed }).onConflictDoUpdate({ target: [tenantFeedEntitlements.tenantId, tenantFeedEntitlements.feedKey], set: { allowed } });
    await audit(tx, { ...actor(ctx), tenantId, action: "intel.entitlement", targetType: "intel_feed", targetId: key, detail: { allowed } });
  });
}

export class SightingRefused extends Error {
  constructor(reason: string) {
    super(`sighting refused: ${reason}`);
    this.name = "SightingRefused";
  }
}

/** Sightings feedback loop state for the caller's tenants. */
export async function sightingQueue(ctx: AccessContext) {
  return scoped(ctx, "intel:share", (tx, ids) =>
    tx
      .select({ id: intelMatches.id, tenantName: tenants.name, verdict: intelMatches.verdict, summary: intelMatches.summary, sightingStatus: intelMatches.sightingStatus, matchedAt: intelMatches.matchedAt })
      .from(intelMatches)
      .innerJoin(tenants, eq(tenants.id, intelMatches.tenantId))
      .where(and(inArray(intelMatches.tenantId, ids), eq(intelMatches.verdict, "malicious")))
      .orderBy(desc(intelMatches.matchedAt))
      .limit(100),
  );
}

/** Queue an anonymised OpenCTI sighting for a confirmed match, subject to the tenant's sharing policy. */
export async function requestSighting(ctx: AccessContext, matchId: string) {
  const out = await scoped(ctx, "intel:share", async (tx, ids): Promise<true | { refused: string }> => {
    const [m] = await tx.select({ id: intelMatches.id, tenantId: intelMatches.tenantId, status: intelMatches.sightingStatus }).from(intelMatches).where(and(eq(intelMatches.id, matchId), inArray(intelMatches.tenantId, ids)));
    if (!m) throw new AccessDenied("match not found");
    const [t] = await tx.select({ settings: tenants.settings }).from(tenants).where(eq(tenants.id, m.tenantId));
    if (!t) throw new AccessDenied("match not found");
    const decision = checkGovernedSighting(await governanceProfile(tx, m.tenantId), t.settings.sharing);
    if (!decision.allowed) {
      // Commit the refusal record, then report it to the caller.
      await tx.update(intelMatches).set({ sightingStatus: "blocked_by_policy" }).where(eq(intelMatches.id, matchId));
      await audit(tx, { ...actor(ctx), tenantId: m.tenantId, action: "intel.sighting_refused", targetType: "intel_match", targetId: matchId, detail: { reason: decision.reason } });
      return { refused: decision.reason };
    }
    await tx.update(intelMatches).set({ sightingStatus: "queued" }).where(eq(intelMatches.id, matchId));
    await audit(tx, { ...actor(ctx), tenantId: m.tenantId, action: "intel.sighting_request", targetType: "intel_match", targetId: matchId });
    const { queue, QUEUES } = await import("@/lib/queue");
    await queue(QUEUES.intel).add("sighting", { tenantId: m.tenantId, matchId });
    return true;
  });
  if (out !== true) throw new SightingRefused(out.refused);
  return true;
}
