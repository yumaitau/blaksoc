import type { z } from "zod";
import { connectorDef, type ConnectorCategory } from "@/lib/connectors/registry";

export const CATEGORY_LABELS: Record<ConnectorCategory, string> = {
  siem: "SIEM",
  endpoint: "Endpoint",
  identity: "Identity",
  network: "Network",
  cloud: "Cloud",
  collaboration: "Collaboration",
  ticketing: "Ticketing",
  threat_intel: "Threat intelligence",
  ai: "AI",
  backup: "Backup",
};
export const CATEGORY_ORDER = Object.keys(CATEGORY_LABELS) as ConnectorCategory[];

/** Starting configuration for the "Add integration" form. Non-secret values only. */
const EXAMPLES: Record<string, Record<string, unknown>> = {
  wazuh: { apiUrl: "https://wazuh-manager.internal:55000", indexerUrl: "https://wazuh-indexer.internal:9200", region: "ap-southeast-2", tlsVerify: true },
  demo: { agents: [{ id: "001", name: "demo-ws-01", group: "demo", os: "Windows 11", ip: "10.20.0.11" }] },
  opencti: { url: "https://opencti.internal", region: "ap-southeast-2", tlsVerify: true },
  "opencti-fixture": {},
  webhook: { url: "https://hooks.example.com/blaksoc", events: ["incident.created", "approval.requested"] },
  teams: { events: ["incident.created", "approval.requested"] },
  slack: { events: ["incident.created", "approval.requested"] },
  ollama: { baseUrl: "http://ollama:11434/v1", model: "llama3.1:8b", region: "au-self-hosted", country: "AU" },
  vllm: { baseUrl: "http://vllm:8000/v1", model: "meta-llama/Llama-3.1-8B-Instruct", region: "au-self-hosted", country: "AU" },
  "azure-openai": { baseUrl: "https://<resource>.openai.azure.com/openai/deployments/<deployment>", model: "<deployment>", apiVersion: "2024-10-21", region: "australiaeast", country: "AU" },
  "openai-compatible": { baseUrl: "https://api.example.com/v1", model: "<model>", region: "<processing region>", country: "AU" },
  bedrock: { region: "ap-southeast-2", model: "anthropic.claude-sonnet-4-5-20250929-v1:0" },
  entra: { azureTenantId: "00000000-0000-0000-0000-000000000000", mode: "live", subscribedSkus: [] },
  "google-workspace": { customerId: "my_customer", domain: "example.org", mode: "fixture" },
  sms: { from: "+61400000000", mode: "fixture", events: ["incident.created"] },
  voice: { from: "+61400000000", mode: "fixture", events: ["incident.created"] },
  email: { host: "smtp.example.com", port: 587, from: "soc@example.com", mode: "fixture", events: ["incident.created"] },
  syslog: { region: "ap-southeast-2" },
  velociraptor: { mode: "fixture" },
  defender: { tenantDomain: "example.org", mode: "fixture" },
  cloudflare: { accountId: "00000000000000000000000000000000", listName: "blaksoc-block", mode: "fixture" },
  fortinet: { host: "https://firewall.example", addressGroup: "blaksoc-block", mode: "fixture" },
  sophos: { centralId: "sophos-central-example", region: "au", mode: "fixture" },
  veeam: { mode: "fixture", staleHours: 24, systems: [] },
};

export function exampleConfig(provider: string): Record<string, unknown> {
  return EXAMPLES[provider] ?? {};
}

/** Secret field names for a connector, read from its zod schema. Values are never read back. */
export function secretFields(provider: string): { key: string; optional: boolean }[] {
  const schema = connectorDef(provider)?.secrets as unknown as { shape?: Record<string, z.ZodType> } | undefined;
  if (!schema?.shape) return [];
  return Object.entries(schema.shape).map(([key, s]) => ({ key, optional: s.safeParse(undefined).success }));
}
