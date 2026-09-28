import type { IntelMatch } from "@/db/schema";
import type { Observable } from "./observables";

export type SightingInput = {
  openctiId: string;
  firstSeen: Date;
  lastSeen: Date;
  count: number;
  /** OpenCTI identity id the sighting is attributed to — an anonymised sector identity by default. */
  whereSightedIdentityId: string;
  markingDefinitionIds: string[];
  description: string;
};

export type CveContext = { cve: string; threats: { id: string; name: string; type: string }[] };

export interface IntelProvider {
  readonly kind: string;
  lookup(observables: Observable[]): Promise<IntelMatch[]>;
  cveContext(cves: string[]): Promise<CveContext[]>;
  search(term: string, types?: string[]): Promise<IntelSearchResult[]>;
  createSighting(input: SightingInput): Promise<{ id: string }>;
  ensureIdentity(name: string, sector?: string): Promise<string>;
  createReport(input: { name: string; description: string; published: Date; externalUrl: string; labels: string[]; cves: string[] }): Promise<{ id: string }>;
  addLabels(openctiId: string, labels: string[]): Promise<void>;
  health(): Promise<{ ok: boolean; latencyMs: number; detail: Record<string, unknown>; error?: string }>;
}

export type IntelSearchResult = {
  id: string;
  entityType: string;
  name: string;
  description: string | null;
  labels: string[];
  markings: string[];
  score: number | null;
  createdBy: string | null;
  modified: string | null;
};

export function scoreToVerdict(score: number | null, hasIndicator: boolean, labels: string[]): IntelMatch["verdict"] {
  if (labels.some((l) => /benign|whitelist|allowlist|false-positive/i.test(l))) return "benign";
  if (score != null && score >= 70) return "malicious";
  if ((score != null && score >= 40) || hasIndicator) return "suspicious";
  return "unknown";
}
