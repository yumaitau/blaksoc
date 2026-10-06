import { assertAuRegion, AU_ARCHIVE_REGIONS } from "@/lib/syslog/retain";

/** `AU` is the policy flag. Bucket regions are the archive list. */
export function allowedDataRegions(): readonly string[] {
  return ["AU", ...AU_ARCHIVE_REGIONS];
}

export function regionStoresOutsideAustralia(region: string): boolean {
  return !allowedDataRegions().includes(region);
}

export type DataPlaneRegions = {
  opensearch: string;
  wazuhIndexer: string;
  opencti: string;
};

/** Names the hosting profile must account for. Order is the check order. */
export const HOSTING_COMPONENT_NAMES = ["ai-policy", "syslog-archive", "opensearch", "wazuh-indexer", "opencti"] as const;

/** Storage components must name an archive region. The AI flag `AU` is not a bucket region. */
export function assertDataPlaneStoresInAustralia(plane: DataPlaneRegions): void {
  assertAuRegion(plane.opensearch);
  assertAuRegion(plane.wazuhIndexer);
  assertAuRegion(plane.opencti);
}

/**
 * Boot check for the worker. All three unset means local dev. One or two set is a broken profile.
 * A value outside `ap-southeast-2` and `ap-southeast-4` throws.
 */
export function assertHostingEnv(env: Record<string, string | undefined>): void {
  const opensearch = env.OPENSEARCH_REGION ?? "";
  const wazuhIndexer = env.WAZUH_INDEXER_REGION ?? "";
  const opencti = env.OPENCTI_REGION ?? "";
  const present = [opensearch, wazuhIndexer, opencti].filter((value) => value !== "");
  if (present.length === 0) return;
  if (present.length !== 3) throw new Error("data plane region is incomplete");
  assertDataPlaneStoresInAustralia({ opensearch, wazuhIndexer, opencti });
}

/** Region advertised by a running OpenSearch or Wazuh indexer node. */
export function assertSearchNodeInAustralia(attributes: Record<string, string> | undefined): string {
  const region = attributes?.region;
  if (!region) throw new Error("search node has no region attribute");
  assertAuRegion(region);
  return region;
}

type SearchNodePayload = { nodes?: Record<string, { attributes?: Record<string, string> }> };

/** First node in an OpenSearch `_nodes` document. */
export function firstSearchNodeAttributes(payload: unknown): Record<string, string> | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  const nodes = (payload as SearchNodePayload).nodes;
  if (!nodes) return undefined;
  for (const node of Object.values(nodes)) return node?.attributes;
  return undefined;
}

export function hostingComponents(
  aiResidency: string,
  archiveRegion: string,
  plane: DataPlaneRegions,
): { name: string; region: string }[] {
  return [
    { name: "ai-policy", region: aiResidency },
    { name: "syslog-archive", region: archiveRegion },
    { name: "opensearch", region: plane.opensearch },
    { name: "wazuh-indexer", region: plane.wazuhIndexer },
    { name: "opencti", region: plane.opencti },
  ];
}

const WORLD_EGRESS = new Set(["0.0.0.0/0", "::/0"]);

/** True when a worker egress CIDR can reach a network that is not pinned to one region. */
export function egressOpensTheWorld(cidrs: readonly string[]): boolean {
  return cidrs.some((cidr) => WORLD_EGRESS.has(cidr.trim()));
}

/**
 * True when web or worker can reach the public internet at all: any-port world CIDRs, or the
 * chart's public HTTPS rule (TCP 443 to public addresses). Public HTTPS is the default because
 * Entra sign-in, Microsoft Graph and the public intel feeds need it; it is not region-pinned,
 * so which tenant data may leave is enforced in the app by the data governance profile.
 */
export function egressReachesPublicInternet(policy: { egressCidrs?: readonly string[]; publicHttps?: boolean }): boolean {
  return egressOpensTheWorld(policy.egressCidrs ?? []) || policy.publicHttps !== false;
}

export function componentsOutsideAustralia(rows: { region: string }[]): string[] {
  return rows.filter((row) => regionStoresOutsideAustralia(row.region)).map((row) => row.region);
}

/** First `key: scalar` in a small Helm values file. */
export function helmScalar(yaml: string, key: string): string | null {
  for (const line of yaml.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith(`${key}:`)) continue;
    let value = trimmed.slice(key.length + 1).trim();
    const hash = value.indexOf(" #");
    if (hash >= 0) value = value.slice(0, hash).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    return value;
  }
  return null;
}

/** First scalar under a top-level block. Stops at the next sibling key. */
export function helmBlockScalar(yaml: string, block: string, key: string): string | null {
  const lines = yaml.split("\n");
  let inBlock = false;
  let indent = 0;
  for (const line of lines) {
    if (!inBlock) {
      const match = new RegExp(`^(\\s*)${block}:\\s*$`).exec(line);
      const captured = match?.[1];
      if (captured === undefined) continue;
      inBlock = true;
      indent = captured.length;
      continue;
    }
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const current = line.match(/^(\s*)/)?.[1]?.length ?? 0;
    if (current <= indent) return null;
    const trimmed = line.trim();
    if (!trimmed.startsWith(`${key}:`)) continue;
    return trimmed.slice(key.length + 1).trim();
  }
  return null;
}
