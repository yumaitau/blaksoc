/**
 * Provider-neutral contract for SIEM/XDR sources. blakSOC never depends on a vendor's
 * data shapes outside the adapter that implements this interface.
 */

export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export type NormalisedAlert = {
  externalId: string;
  ruleId: string | null;
  title: string;
  description: string | null;
  category: string | null;
  /** Vendor-native severity value, kept for transparency. */
  siemSeverity: number | null;
  severity: Severity;
  occurredAt: Date;
  /** Provider-side asset id (e.g. Wazuh agent id) used to map to a blakSOC asset. */
  assetExternalId: string | null;
  hostname: string | null;
  userName: string | null;
  attackTechniques: string[];
  /** Provider selector value used to route the alert to a tenant (e.g. Wazuh agent group). */
  routingKeys: string[];
  raw: Record<string, unknown>;
};

export type NormalisedAsset = {
  externalId: string;
  kind: "endpoint" | "server" | "network_device" | "cloud_resource";
  name: string;
  hostname: string | null;
  ips: string[];
  os: string | null;
  macs: string[];
  agentStatus: string | null;
  lastSeen: Date | null;
  routingKeys: string[];
  raw: Record<string, unknown>;
};

export type NormalisedVulnerability = {
  assetExternalId: string;
  cve: string;
  title: string | null;
  packageName: string | null;
  packageVersion: string | null;
  fixedVersion: string | null;
  cvss: number | null;
};

export type AlertQuery = {
  since?: Date;
  until?: Date;
  routingKeys?: string[];
  limit?: number;
  /** Provider-native query (e.g. OpenSearch query_string) for hunting and deployed detections. */
  query?: string;
  afterCursor?: string;
};

export type ResponseActionRequest = {
  action: "isolate_endpoint" | "release_endpoint" | "block_ip" | "kill_process" | "custom";
  assetExternalId: string;
  params?: Record<string, unknown>;
};

export type ResponseActionResult = { ok: boolean; message: string; providerRef?: string };

export type ProviderHealth = {
  ok: boolean;
  latencyMs: number;
  detail: Record<string, unknown>;
  error?: string;
};

export interface SecurityEventProvider {
  readonly kind: string;
  getAlerts(q: AlertQuery): Promise<{ alerts: NormalisedAlert[]; cursor: string | null }>;
  getAlert(externalId: string): Promise<NormalisedAlert | null>;
  searchEvents(q: AlertQuery): Promise<{ total: number; events: Record<string, unknown>[] }>;
  getAssets(routingKeys?: string[]): Promise<NormalisedAsset[]>;
  getAsset(externalId: string): Promise<NormalisedAsset | null>;
  getVulnerabilities?(assetExternalIds?: string[]): Promise<NormalisedVulnerability[]>;
  /** Actions this provider can execute; the SOAR layer refuses anything else. */
  supportedActions(): ResponseActionRequest["action"][];
  executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult>;
  health(): Promise<ProviderHealth>;
}
