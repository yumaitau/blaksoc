import { inArray } from "drizzle-orm";
import type { DbOrTx } from "@/db/client";
import { intelFeeds, tenantFeedEntitlements, type IntelContext, type IntelMatch } from "@/db/schema";
import { redis } from "@/lib/redis";
import { ENRICHABLE, type Observable } from "./observables";
import type { IntelProvider } from "./types";

const TTL_HIT = 60 * 60; // intel on known-bad changes slowly
const TTL_MISS = 15 * 60; // re-check unknowns sooner so new intel lands quickly
const cacheKey = (provider: string, o: Observable) => `intel:${provider}:${o.type}:${o.value}`;

/**
 * Looks up observables in threat intel, with a shared Redis cache. Intel itself is
 * global (not tenant data), so caching across tenants is safe; entitlement filtering is
 * applied per tenant after the cache.
 */
export async function lookupWithCache(provider: IntelProvider, observables: Observable[]): Promise<{ matches: IntelMatch[]; cacheHits: number }> {
  const candidates = observables.filter((o) => ENRICHABLE.has(o.type)).slice(0, 50);
  if (!candidates.length) return { matches: [], cacheHits: 0 };
  const r = redis();
  const cached = await r.mget(...candidates.map((o) => cacheKey(provider.kind, o)));
  const matches: IntelMatch[] = [];
  const misses: Observable[] = [];
  candidates.forEach((o, i) => {
    const c = cached[i];
    if (c == null) misses.push(o);
    else matches.push(...(JSON.parse(c) as IntelMatch[]));
  });
  if (misses.length) {
    const fresh = await provider.lookup(misses);
    const pipe = r.pipeline();
    for (const o of misses) {
      const mine = fresh.filter((m) => m.observable.type === o.type && m.observable.value === o.value);
      pipe.set(cacheKey(provider.kind, o), JSON.stringify(mine), "EX", mine.length ? TTL_HIT : TTL_MISS);
      matches.push(...mine);
    }
    await pipe.exec();
  }
  return { matches, cacheHits: candidates.length - misses.length };
}

/** Drop intel from commercial feeds the tenant is not licensed for. */
export async function filterByEntitlement(tx: DbOrTx, tenantId: string, matches: IntelMatch[]): Promise<IntelMatch[]> {
  const feeds = await tx.select().from(intelFeeds);
  const commercialSources = new Map(feeds.filter((f) => f.commercial).map((f) => [f.connector.createdBy ?? f.name, f.key]));
  if (!commercialSources.size) return matches;
  const ents = await tx
    .select()
    .from(tenantFeedEntitlements)
    .where(inArray(tenantFeedEntitlements.feedKey, [...commercialSources.values()]));
  const allowed = new Set(ents.filter((e) => e.tenantId === tenantId && e.allowed).map((e) => e.feedKey));
  return matches.filter((m) => {
    const feed = m.source ? commercialSources.get(m.source) : undefined;
    return !feed || allowed.has(feed);
  });
}

export function summariseIntel(matches: IntelMatch[]): IntelContext {
  const rank = { malicious: 3, suspicious: 2, unknown: 1, benign: 0 } as const;
  const verdict = matches.reduce<IntelContext["verdict"]>((v, m) => (rank[m.verdict] > rank[v] ? m.verdict : v), "unknown");
  return { verdict: matches.length ? verdict : "unknown", matches, checkedAt: new Date().toISOString() };
}
