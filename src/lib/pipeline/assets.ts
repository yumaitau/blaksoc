import { and, arrayOverlaps, eq, sql } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { assetSources, assets } from "@/db/schema";
import type { NormalisedAsset } from "@/lib/providers/types";

/**
 * Identity keys used to merge the same machine reported by several integrations.
 * IPs are deliberately excluded: DHCP reuse would merge unrelated devices.
 */
export function dedupeKeys(a: { hostname: string | null; macs?: string[] }, integrationId: string, externalId: string): string[] {
  const keys = [`src:${integrationId}:${externalId}`];
  if (a.hostname) keys.push(`host:${a.hostname.toLowerCase().split(".")[0]}`);
  for (const m of a.macs ?? []) keys.push(`mac:${m.toLowerCase().replaceAll("-", ":")}`);
  return keys;
}

/** Upsert provider assets into the unified inventory for one tenant. Returns externalId → assetId. */
export async function syncAssets(tx: Tx, tenantId: string, integrationId: string, list: NormalisedAsset[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  for (const a of list) {
    const keys = dedupeKeys(a, integrationId, a.externalId);
    const [existing] = await tx
      .select({ id: assets.id, dedupeKeys: assets.dedupeKeys })
      .from(assets)
      .where(and(eq(assets.tenantId, tenantId), arrayOverlaps(assets.dedupeKeys, keys)))
      .limit(1);

    let assetId: string;
    if (existing) {
      assetId = existing.id;
      await tx
        .update(assets)
        .set({
          hostname: a.hostname,
          ips: a.ips,
          os: a.os,
          agentStatus: a.agentStatus,
          lastSeen: a.lastSeen ?? new Date(),
          dedupeKeys: [...new Set([...existing.dedupeKeys, ...keys])],
        })
        .where(eq(assets.id, assetId));
    } else {
      const [row] = await tx
        .insert(assets)
        .values({ tenantId, kind: a.kind, name: a.name, hostname: a.hostname, ips: a.ips, os: a.os, agentStatus: a.agentStatus, dedupeKeys: keys, lastSeen: a.lastSeen ?? new Date() })
        .returning({ id: assets.id });
      assetId = row!.id;
    }
    await tx
      .insert(assetSources)
      .values({ tenantId, assetId, integrationId, externalId: a.externalId, raw: a.raw })
      .onConflictDoUpdate({ target: [assetSources.integrationId, assetSources.externalId], set: { assetId, raw: a.raw, lastSyncedAt: sql`now()` } });
    out.set(a.externalId, assetId);
  }
  return out;
}
