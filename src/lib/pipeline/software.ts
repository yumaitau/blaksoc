import type { NormalisedSoftware } from "@/lib/providers/types";

/** Upper bound per asset; a build server can list thousands of packages. */
export const SOFTWARE_PER_ASSET = 3000;

/** Group a provider's package inventory by blakSOC asset: unique by name and version, sorted, capped. */
export function softwareByAsset(list: NormalisedSoftware[], assetOf: (externalId: string) => string | undefined) {
  const out = new Map<string, Map<string, { name: string; version: string }>>();
  for (const p of list) {
    const assetId = assetOf(p.assetExternalId);
    if (!assetId) continue;
    const rows = out.get(assetId) ?? new Map();
    out.set(assetId, rows);
    rows.set(`${p.name}\0${p.version}`, { name: p.name, version: p.version });
  }
  return new Map([...out].map(([id, rows]) => [id, [...rows.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)).slice(0, SOFTWARE_PER_ASSET)]));
}
