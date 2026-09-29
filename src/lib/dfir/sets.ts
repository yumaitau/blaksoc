/** Standard Velociraptor artifact sets. Each one is intrusive and waits for approval. */
export const ARTIFACT_SETS = ["triage", "persistence", "browser_history", "event_logs"] as const;
export type ArtifactSet = (typeof ARTIFACT_SETS)[number];

export const ARTIFACT_LABELS: Record<ArtifactSet, string> = {
  triage: "Triage",
  persistence: "Persistence",
  browser_history: "Browser history",
  event_logs: "Event logs",
};

export const COLLECTION_STATUS_LABEL: Record<string, string> = {
  pending_approval: "Waiting for approval",
  scheduled: "Scheduled",
  complete: "Complete",
  rejected: "Rejected",
};

/** Low-bandwidth sites collect a few machines and delay the upload. */
export const LOW_BANDWIDTH_HOSTS = 3;
export const LOW_BANDWIDTH_DELAY_MS = 15 * 60_000;

export function isArtifactSet(value: string): value is ArtifactSet {
  return (ARTIFACT_SETS as readonly string[]).includes(value);
}
