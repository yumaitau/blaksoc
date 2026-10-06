import { gunzipSync } from "node:zlib";
import { and, eq, sql } from "drizzle-orm";
import { adminDb } from "@/db/client";
import { advisories, assets, cveIntel, dataGovernance, intelFeeds, intelMatches, tenants, vulnerabilities } from "@/db/schema";
import { checkGovernedSighting } from "@/lib/governance/policy";
import { governanceProfile } from "@/lib/services/governance";
import { extractAdvisoryTechniques } from "@/lib/detections/advisory-coverage";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { intelProviderFor } from "@/lib/connectors/instances";
import { scoreVulnerability } from "@/lib/risk/engine";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://api.first.org/data/v1/epss";
/** Whole-dataset download. Fetching it discloses nothing about which CVEs a tenant has. */
const EPSS_BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

/** Rows of the EPSS bulk CSV for the wanted CVEs. Comment lines start with #. */
export function parseEpssCsv(csv: string, wanted: ReadonlySet<string>): Map<string, { epss: number; percentile: number }> {
  const out = new Map<string, { epss: number; percentile: number }>();
  for (const line of csv.split("\n")) {
    if (!line.startsWith("CVE-")) continue;
    const [cve, score, percentile] = line.trim().split(",");
    if (cve && wanted.has(cve)) out.set(cve, { epss: Number(score), percentile: Number(percentile) });
  }
  return out;
}

/** CVEs present only in tenants whose governance profile locks data to Australia. No profile row means locked. */
async function lockedOnlyCves(db: ReturnType<typeof adminDb>, cves: string[]): Promise<Set<string>> {
  const rows = await db
    .select({ cve: vulnerabilities.cve, locked: sql<boolean>`coalesce((${dataGovernance.profile}->>'residencyLock')::boolean, true)` })
    .from(vulnerabilities)
    .leftJoin(dataGovernance, eq(dataGovernance.tenantId, vulnerabilities.tenantId));
  const open = new Set(rows.filter((r) => !r.locked).map((r) => r.cve));
  return new Set(cves.filter((c) => !open.has(c)));
}

/** Refresh CISA KEV + FIRST EPSS + OpenCTI context for every CVE present in any tenant. */
export async function refreshCveIntel(log: (m: string) => void) {
  const db = adminDb();
  const cves = (await db.selectDistinct({ cve: vulnerabilities.cve }).from(vulnerabilities)).map((r) => r.cve).filter((c) => /^CVE-\d{4}-\d+$/.test(c));
  if (!cves.length) return;

  const kev = new Map<string, { dateAdded: string; dueDate: string; ransomware: boolean; name: string }>();
  try {
    const data = (await (await fetch(KEV_URL, { signal: AbortSignal.timeout(30_000) })).json()) as {
      vulnerabilities: { cveID: string; dateAdded: string; dueDate: string; knownRansomwareCampaignUse: string; vulnerabilityName: string }[];
    };
    for (const v of data.vulnerabilities) kev.set(v.cveID, { dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse === "Known", name: v.vulnerabilityName });
  } catch (e) {
    log(`KEV fetch failed: ${(e as Error).message}`);
  }

  // CVEs held only by residency-locked tenants are never sent abroad. They are read from the public bulk file instead.
  const locked = await lockedOnlyCves(db, cves);
  const epss = new Map<string, { epss: number; percentile: number }>();
  const queryable = cves.filter((c) => !locked.has(c));
  for (let i = 0; i < queryable.length; i += 100) {
    try {
      const batch = queryable.slice(i, i + 100);
      const data = (await (await fetch(`${EPSS_URL}?cve=${batch.join(",")}`, { signal: AbortSignal.timeout(30_000) })).json()) as { data: { cve: string; epss: string; percentile: string }[] };
      for (const d of data.data) epss.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile) });
    } catch (e) {
      log(`EPSS fetch failed: ${(e as Error).message}`);
    }
  }
  if (locked.size) {
    try {
      const res = await fetch(EPSS_BULK_URL, { signal: AbortSignal.timeout(120_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      for (const [cve, score] of parseEpssCsv(gunzipSync(Buffer.from(await res.arrayBuffer())).toString("utf8"), locked)) epss.set(cve, score);
    } catch (e) {
      log(`EPSS bulk fetch failed: ${(e as Error).message}`);
    }
  }

  const intel = await intelProviderFor(db, null);
  const ctxs = intel ? await intel.provider.cveContext(cves.slice(0, 500)).catch(() => []) : [];
  const threatMap = new Map(ctxs.map((c) => [c.cve, c.threats]));

  for (const cve of cves) {
    const k = kev.get(cve);
    const e = epss.get(cve);
    const threats = threatMap.get(cve);
    await db
      .insert(cveIntel)
      .values({ cve, kev: !!k, kevDateAdded: k?.dateAdded, kevDueDate: k?.dueDate, kevRansomware: k?.ransomware ?? false, epss: e?.epss, epssPercentile: e?.percentile, summary: k?.name, openctiThreats: threats?.length ?? 0, openctiRefs: threats ?? [] })
      .onConflictDoUpdate({
        target: cveIntel.cve,
        set: {
          // Only overwrite from sources that actually responded this run.
          ...(kev.size ? { kev: !!k, kevDateAdded: k?.dateAdded ?? null, kevDueDate: k?.dueDate ?? null, kevRansomware: k?.ransomware ?? false } : {}),
          ...(e ? { epss: e.epss, epssPercentile: e.percentile } : {}),
          ...(threats ? { openctiThreats: threats.length, openctiRefs: threats } : {}),
          updatedAt: new Date(),
        },
      });
  }
  log(`cve intel refreshed: ${cves.length} CVEs, ${cves.filter((c) => kev.has(c)).length} on KEV`);
}

/** Recompute patch priority for every open vulnerability in a tenant, then roll up asset risk. */
export async function rescoreVulnerabilities(tenantId: string) {
  await withScope(systemScope(tenantId), async (tx) => {
    const rows = await tx
      .select({ v: vulnerabilities, a: assets, c: cveIntel })
      .from(vulnerabilities)
      .innerJoin(assets, eq(assets.id, vulnerabilities.assetId))
      .leftJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve))
      .where(and(eq(vulnerabilities.tenantId, tenantId), eq(vulnerabilities.status, "open")));
    const observed = new Set(
      (await tx.execute<{ cve: string }>(sql`select distinct value as cve from observables where tenant_id = ${tenantId} and type = 'cve'`)).map((r) => r.cve),
    );
    for (const { v, a, c } of rows) {
      const { score, factors } = scoreVulnerability({
        cve: v.cve,
        cvss: v.cvss ?? c?.cvss ?? null,
        epss: c?.epss ?? null,
        epssPercentile: c?.epssPercentile ?? null,
        kev: c?.kev ?? false,
        kevRansomware: c?.kevRansomware ?? false,
        kevDueDate: c?.kevDueDate ?? null,
        openctiThreats: c?.openctiRefs ?? [],
        asset: { id: a.id, name: a.name, criticality: a.criticality, exposure: a.exposure },
        observedExploitation: observed.has(v.cve),
      });
      if (score !== v.priorityScore || JSON.stringify(factors) !== JSON.stringify(v.priorityFactors)) {
        await tx.update(vulnerabilities).set({ priorityScore: score, priorityFactors: factors }).where(eq(vulnerabilities.id, v.id));
      }
    }
    // Asset risk = worst of open alert risk and patch priority.
    await tx.execute(sql`
      update assets s set risk_score = greatest(
        coalesce((select max(a.risk_score) from alerts a where a.asset_id = s.id and a.status not in ('RESOLVED','FALSE_POSITIVE')), 0),
        coalesce((select max(v.priority_score) from vulnerabilities v where v.asset_id = s.id and v.status = 'open'), 0))
      where s.tenant_id = ${tenantId}`);
  });
}

type RssItem = { title: string; link: string; pubDate: string | null; description: string; guid: string };

export function parseRss(xml: string): RssItem[] {
  const tag = (block: string, name: string) => {
    const m = new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, "i").exec(block);
    return m
      ? m[1]!
          .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
          .replace(/<[^>]+>/g, " ")
          .replace(/&amp;/g, "&")
          .replace(/&lt;/g, "<")
          .replace(/&gt;/g, ">")
          .replace(/&#39;|&apos;/g, "'")
          .replace(/&quot;/g, '"')
          .replace(/\s+/g, " ")
          .trim()
      : "";
  };
  return [...xml.matchAll(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi)].map((m) => {
    const b = m[0];
    const link = tag(b, "link") || /<link[^>]*href="([^"]+)"/i.exec(b)?.[1] || "";
    return {
      title: tag(b, "title"),
      link,
      pubDate: tag(b, "pubDate") || tag(b, "updated") || tag(b, "published") || null,
      description: tag(b, "description") || tag(b, "summary"),
      guid: tag(b, "guid") || tag(b, "id") || link,
    };
  });
}

const SECTOR_HINTS: [RegExp, string][] = [
  [/australia|\bACSC\b|\bASD\b|cyber\.gov\.au/i, "AUSTRALIA"],
  [/government|agency|federal|state entities/i, "GOVERNMENT"],
  [/health|hospital|medical/i, "HEALTHCARE"],
  [/critical infrastructure|\bOT\b|\bICS\b|SCADA|energy|water utilit/i, "CRITICAL_INFRASTRUCTURE"],
  [/small business|\bSMB\b|small and medium/i, "SMB"],
  [/bank|financ|payment/i, "FINANCE"],
  [/universit|school|education/i, "EDUCATION"],
];

export function tagAdvisory(feedKey: string, text: string): string[] {
  return [...new Set([...(feedKey.startsWith("acsc") ? ["AUSTRALIA"] : []), ...SECTOR_HINTS.filter(([rx]) => rx.test(text)).map(([, t]) => t)])];
}

/** Fields stored for one advisory item. Callers pass already-fetched text. */
export function advisoryFields(feedKey: string, title: string, description: string) {
  const text = `${title} ${description}`;
  const cves = [...new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) ?? []).map((c) => c.toUpperCase()))];
  return { cves, tags: tagAdvisory(feedKey, text), attackTechniques: extractAdvisoryTechniques(text), summary: description.slice(0, 2000) };
}

/** Pull public advisory feeds (ACSC / CISA / CERTs) configured as intel_feeds of category "advisory". */
export async function ingestAdvisories(log: (m: string) => void) {
  const db = adminDb();
  const feeds = await db.select().from(intelFeeds).where(and(eq(intelFeeds.category, "advisory"), eq(intelFeeds.enabled, true)));
  const intel = await intelProviderFor(db, null);
  for (const f of feeds) {
    if (!f.connector.url) continue;
    try {
      const res = await fetch(f.connector.url, { signal: AbortSignal.timeout(30_000), headers: { "user-agent": "blakSOC advisory ingest" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      let added = 0;
      for (const item of parseRss(await res.text()).slice(0, 50)) {
        const fields = advisoryFields(f.key, item.title, item.description);
        const inserted = await db
          .insert(advisories)
          .values({ source: f.name, externalId: `${f.key}:${item.guid}`, title: item.title, url: item.link, summary: fields.summary, publishedAt: item.pubDate ? new Date(item.pubDate) : null, cves: fields.cves, tags: fields.tags, attackTechniques: fields.attackTechniques })
          .onConflictDoNothing()
          .returning({ id: advisories.id });
        if (!inserted.length) continue;
        added++;
        // Normalise into OpenCTI as a STIX Report so analysts see it alongside other intel.
        if (intel?.provider.kind === "opencti") {
          const r = await intel.provider
            .createReport({ name: item.title, description: item.description.slice(0, 4000), published: item.pubDate ? new Date(item.pubDate) : new Date(), externalUrl: item.link, labels: fields.tags.map((t) => t.toLowerCase()), cves: fields.cves })
            .catch(() => null);
          if (r) await db.update(advisories).set({ openctiReportId: r.id }).where(eq(advisories.id, inserted[0]!.id));
        }
      }
      log(`advisories ${f.key}: +${added}`);
    } catch (e) {
      log(`advisories ${f.key} failed: ${(e as Error).message}`);
    }
  }
}

/** Feedback loop: publish a sighting to OpenCTI under the tenant's sharing policy. Never names the customer unless allowed. */
export async function createSighting(tenantId: string, matchId: string) {
  const intel = await intelProviderFor(adminDb(), tenantId);
  await withScope(systemScope(tenantId), async (tx) => {
    const [m] = await tx.select().from(intelMatches).where(eq(intelMatches.id, matchId));
    const [t] = await tx.select().from(tenants).where(eq(tenants.id, tenantId));
    if (!m || !t) return;
    const decision = checkGovernedSighting(await governanceProfile(tx, tenantId), t.settings.sharing);
    if (!decision.allowed || !intel) {
      await tx.update(intelMatches).set({ sightingStatus: "blocked_by_policy" }).where(eq(intelMatches.id, matchId));
      await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "intel.sighting_refused", targetType: "intel_match", targetId: matchId, detail: { reason: decision.allowed ? "no intel connector in an allowed region" : decision.reason } });
      return;
    }
    // The narrower of the tenant setting and steward consent applies.
    const { attribution, maxTlp } = decision;
    const sector = t.sectors.find((s) => s !== "AUSTRALIA") ?? "SMB";
    const identityName = attribution === "named" ? t.name : `blakSOC AU ${sector.replaceAll("_", " ").toLowerCase()} sector`;
    const identityId = await intel.provider.ensureIdentity(identityName, attribution === "anonymised" ? sector : undefined);
    const s = await intel.provider.createSighting({
      openctiId: m.openctiId,
      firstSeen: m.matchedAt,
      lastSeen: m.matchedAt,
      count: 1,
      whereSightedIdentityId: identityId,
      markingDefinitionIds: [],
      description: `Observed by blakSOC (${maxTlp}).${attribution === "anonymised" ? " Customer identity withheld per sharing policy." : ""}`,
    });
    await tx.update(intelMatches).set({ sightingStatus: "shared", sightingId: s.id }).where(eq(intelMatches.id, matchId));
    await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "intel.sighting_created", targetType: "intel_match", targetId: matchId, detail: { attribution, maxTlp, identityName } });
  });
}
