import { z } from "zod";
import { FixtureIntelProvider } from "@/lib/intel/fixture";
import { OpenCtiProvider } from "@/lib/intel/opencti";
import type { IntelProvider } from "@/lib/intel/types";
import { googleWorkspaceConnector } from "@/lib/providers/google/connector";
import { entraConnector } from "@/lib/providers/m365/connector";
import { CloudflareProvider, DefenderProvider, FortinetProvider, SophosProvider } from "@/lib/providers/containment";
import { DemoProvider } from "@/lib/providers/demo";
import type { ProviderHealth, SecurityEventProvider } from "@/lib/providers/types";
import { SyslogProvider } from "@/lib/providers/syslog";
import { TawnyProvider } from "@/lib/providers/tawny";
import { VeeamProvider } from "@/lib/providers/veeam";
import { WazuhProvider } from "@/lib/providers/wazuh";
import { veeamConfig } from "@/lib/backup/status";
import { BedrockProvider, OpenAICompatibleProvider } from "@/lib/ai/providers";
import type { AIProvider } from "@/lib/ai/types";
import { EmailNotifier, SmsNotifier, VoiceNotifier } from "./au-notify";
import { WebhookNotifier, type Notifier } from "./notify";

/**
 * Connector SDK. A connector declares its config (non-secret, shown in UI) and secrets
 * (encrypted at rest, write-only from the UI) as zod schemas, plus the capabilities it
 * implements. Adding a vendor = adding one definition here.
 */

export type ConnectorCategory = "ai" | "siem" | "endpoint" | "identity" | "network" | "cloud" | "collaboration" | "ticketing" | "threat_intel" | "backup";
export type Capability = "inference" | "events" | "assets" | "vulnerabilities" | "response" | "intel" | "notify" | "ticket" | "identity_response";

export type ConnectorInstance =
  | { kind: "events"; provider: SecurityEventProvider }
  | { kind: "intel"; provider: IntelProvider }
  | { kind: "notify"; provider: Notifier }
  | { kind: "ai"; provider: AIProvider }
  | { kind: "backup"; provider: { health(): Promise<ProviderHealth> } };

export type ConnectorDefinition = {
  provider: string;
  name: string;
  category: ConnectorCategory;
  description: string;
  status: "available" | "planned";
  capabilities: Capability[];
  /** Permissions the connector needs in the remote system (documented to admins). */
  remotePermissions: string[];
  config: z.ZodType<Record<string, unknown>>;
  secrets: z.ZodType<Record<string, string>>;
  create?: (config: Record<string, unknown>, secrets: Record<string, string>) => ConnectorInstance;
};

const tls = { tlsVerify: z.boolean().default(true), caPem: z.string().optional() };

const planned = (provider: string, name: string, category: ConnectorCategory, capabilities: Capability[], description: string): ConnectorDefinition => ({
  provider, name, category, capabilities, description, status: "planned", remotePermissions: [],
  config: z.record(z.string(), z.unknown()), secrets: z.record(z.string(), z.string()),
});

export const CONNECTORS: ConnectorDefinition[] = [
  {
    provider: "wazuh",
    name: "Wazuh",
    category: "siem",
    description: "SIEM/XDR telemetry: alerts from the Wazuh indexer, agent inventory, vulnerability states and active response via the Wazuh API.",
    status: "available",
    capabilities: ["events", "assets", "vulnerabilities", "response"],
    remotePermissions: [
      "Wazuh API user with agents:read, active-response:command, cluster:read",
      "Indexer user with read on wazuh-alerts-* and wazuh-states-vulnerabilities-*",
    ],
    config: z.object({
      apiUrl: z.string().url(),
      indexerUrl: z.string().url(),
      alertsIndex: z.string().optional(),
      vulnerabilitiesIndex: z.string().optional(),
      activeResponse: z.record(z.string(), z.union([z.string(), z.object({ windows: z.string().optional(), default: z.string() })])).optional(),
      region: z.enum(["ap-southeast-2", "ap-southeast-4"]),
      ...tls,
    }),
    secrets: z.object({ apiUser: z.string().min(1), apiPassword: z.string().min(1), indexerUser: z.string().min(1), indexerPassword: z.string().min(1) }),
    create: (c, s) => ({ kind: "events", provider: new WazuhProvider(c as never, s as never) }),
  },
  {
    provider: "demo",
    name: "Demo telemetry",
    category: "siem",
    description: "Synthetic Wazuh-shaped telemetry for demonstrations and training. Never use for customers.",
    status: "available",
    capabilities: ["events", "assets", "response"],
    remotePermissions: [],
    config: z.object({ agents: z.array(z.object({ id: z.string(), name: z.string(), group: z.string(), os: z.string(), ip: z.string() })) }),
    secrets: z.object({}),
    create: (c) => ({ kind: "events", provider: new DemoProvider((c as { agents: never }).agents) }),
  },
  {
    provider: "syslog",
    name: "Firewall syslog",
    category: "siem",
    description: "Per-tenant syslog from small-office firewalls. Vector forwards each line. Parsers cover UniFi, Sophos, FortiGate, MikroTik, and DrayTek.",
    status: "available",
    capabilities: ["events"],
    remotePermissions: ["TLS syslog listener or Vector HTTP sink using a per-tenant bearer token"],
    config: z.object({
      tenantId: z.string().uuid().optional(),
      region: z.enum(["ap-southeast-2", "ap-southeast-4"]).default("ap-southeast-2"),
    }),
    secrets: z.object({}),
    create: (c) => ({ kind: "events", provider: new SyslogProvider(typeof c.tenantId === "string" ? c.tenantId : "") }),
  },
  {
    provider: "velociraptor",
    name: "Velociraptor",
    category: "endpoint",
    description: "Per-customer collections and hunts. This build returns fixture results and does not call the gRPC API. Every artifact set waits for approval.",
    status: "available",
    capabilities: ["assets"],
    remotePermissions: ["Velociraptor API client for one org"],
    config: z.object({ mode: z.enum(["fixture", "live"]).default("fixture"), org: z.string().optional() }),
    secrets: z.object({}),
  },
  {
    provider: "opencti",
    name: "OpenCTI",
    category: "threat_intel",
    description: "Authoritative CTI platform: enrichment, STIX 2.1 knowledge, sightings feedback and Australian advisory reports.",
    status: "available",
    capabilities: ["intel"],
    remotePermissions: ["OpenCTI user with KNOWLEDGE, KNOWLEDGE_KNUPDATE (sightings/reports/labels) — no settings access"],
    config: z.object({ url: z.string().url(), region: z.enum(["ap-southeast-2", "ap-southeast-4"]), ...tls }),
    secrets: z.object({ token: z.string().min(1) }),
    create: (c, s) => ({ kind: "intel", provider: new OpenCtiProvider(c as never, s.token!) }),
  },
  {
    provider: "opencti-fixture",
    name: "OpenCTI (demo fixture)",
    category: "threat_intel",
    description: "Deterministic intel fixture for demos and tests.",
    status: "available",
    capabilities: ["intel"],
    remotePermissions: [],
    config: z.object({}),
    secrets: z.object({}),
    create: () => ({ kind: "intel", provider: new FixtureIntelProvider() }),
  },
  {
    provider: "webhook",
    name: "Generic webhook",
    category: "ticketing",
    description: "HMAC-signed JSON webhook for ticketing, chat or automation endpoints.",
    status: "available",
    capabilities: ["notify", "ticket"],
    remotePermissions: [],
    config: z.object({ url: z.string().url(), events: z.array(z.string()).default(["incident.created", "approval.requested"]) }),
    secrets: z.object({ signingSecret: z.string().min(16) }),
    create: (c, s) => ({ kind: "notify", provider: new WebhookNotifier(c.url as string, s.signingSecret!) }),
  },
  {
    provider: "teams",
    name: "Microsoft Teams",
    category: "collaboration",
    description: "Posts incident and approval cards to a Teams channel via a Workflows webhook.",
    status: "available",
    capabilities: ["notify"],
    remotePermissions: ["Teams Workflows 'post to channel when a webhook request is received' URL"],
    config: z.object({ events: z.array(z.string()).default(["incident.created", "approval.requested"]) }),
    secrets: z.object({ webhookUrl: z.string().url() }),
    create: (_c, s) => ({ kind: "notify", provider: new WebhookNotifier(s.webhookUrl!, null, "teams") }),
  },
  {
    provider: "slack",
    name: "Slack",
    category: "collaboration",
    description: "Posts incident and approval notifications via an incoming webhook.",
    status: "available",
    capabilities: ["notify"],
    remotePermissions: ["Slack incoming webhook"],
    config: z.object({ events: z.array(z.string()).default(["incident.created", "approval.requested"]) }),
    secrets: z.object({ webhookUrl: z.string().url() }),
    create: (_c, s) => ({ kind: "notify", provider: new WebhookNotifier(s.webhookUrl!, null, "slack") }),
  },
  ...aiConnectors(),
  entraConnector,
  googleWorkspaceConnector,
  {
    provider: "veeam",
    name: "Veeam",
    category: "backup",
    description: "Veeam backup jobs for protected systems. Fixture results only. This build does not call Veeam.",
    status: "available",
    capabilities: ["assets"],
    remotePermissions: ["Veeam Backup Enterprise Manager read access"],
    config: veeamConfig,
    secrets: z.object({}),
    create: (c) => ({ kind: "backup", provider: new VeeamProvider(veeamConfig.parse(c)) }),
  },
  planned("sentinel", "Microsoft Sentinel", "siem", ["events", "assets"], "Log Analytics incidents and KQL hunting."),
  planned("elastic", "Elastic Security", "siem", ["events", "assets"], "Detection alerts and ES|QL hunting."),
  planned("splunk", "Splunk", "siem", ["events"], "Notable events and SPL searches."),
  planned("security-onion", "Security Onion", "siem", ["events"], "NSM alerts and hunts."),
  planned("graylog", "Graylog", "siem", ["events"], "Event definitions and streams."),
  {
    provider: "defender",
    name: "Microsoft Defender XDR",
    category: "endpoint",
    description: "Device isolation, an antivirus scan, and the vulnerability list. Incidents come in as alerts. Release lifts isolation. Fixture results only. This build does not call Microsoft.",
    status: "available",
    capabilities: ["events", "assets", "response", "vulnerabilities"],
    remotePermissions: ["Machine.Read.All", "Machine.Isolate", "Machine.Scan", "Vulnerability.Read.All", "Alert.Read.All"],
    config: z.object({ tenantDomain: z.string().min(1), mode: z.enum(["fixture", "live"]).default("fixture") }),
    secrets: z.object({ clientId: z.string().min(1), clientSecret: z.string().min(1) }),
    create: (c, s) => ({ kind: "events", provider: new DefenderProvider(c as never, s as never) }),
  },
  {
    provider: "tawny",
    name: "Tawny EDR",
    category: "endpoint",
    description: "Yuma IT's endpoint agent. Alerts with ATT&CK techniques, agent inventory, and kill process by PID. Actions run on the agent's next heartbeat, and blakSOC records the agent's result. Sigma rules deploy as Tawny alert rules. Isolation and release need an agent build with isolation support; current agents report them as failed. Fixture mode returns canned data without calling Tawny.",
    status: "available",
    capabilities: ["events", "assets", "response"],
    remotePermissions: [
      "Tawny API token (twny_) from the customer's Tawny tenant",
      "Viewer role to read alerts, agents and action status; Admin role to run response actions and deploy Sigma rules",
    ],
    config: z.object({
      apiUrl: z.string().url(),
      region: z.enum(["ap-southeast-2", "ap-southeast-4"]),
      mode: z.enum(["fixture", "live"]).default("live"),
      ...tls,
    }),
    secrets: z.object({ apiToken: z.string().regex(/^twny_[A-Za-z0-9_-]{16,}$/, "Tawny API tokens start with twny_") }),
    create: (c, s) => ({ kind: "events", provider: new TawnyProvider(c as never, s as never) }),
  },
  planned("crowdstrike", "CrowdStrike Falcon", "endpoint", ["events", "assets", "response"], "Detections and host containment."),
  planned("sentinelone", "SentinelOne", "endpoint", ["events", "assets", "response"], "Threats and network quarantine."),
  planned("active-directory", "Active Directory", "identity", ["assets", "identity_response"], "On-prem identity via LDAPS agent."),
  {
    provider: "fortinet",
    name: "Fortinet FortiGate",
    category: "network",
    description: "Puts an indicator in one FortiGate address group. Unblock takes it out. Fixture results only. This build does not call the firewall.",
    status: "available",
    capabilities: ["response"],
    remotePermissions: ["REST API admin limited to one firewall address group"],
    config: z.object({
      host: z.string().url(),
      addressGroup: z.string().min(1),
      mode: z.enum(["fixture", "live"]).default("fixture"),
    }),
    secrets: z.object({ apiToken: z.string().min(1) }),
    create: (c, s) => ({ kind: "events", provider: new FortinetProvider(c as never, s as never) }),
  },
  planned("palo-alto", "Palo Alto Networks", "network", ["response"], "EDL / dynamic address group blocking."),
  {
    provider: "cloudflare",
    name: "Cloudflare",
    category: "network",
    description: "Puts an indicator on a WAF custom list and a Zero Trust Gateway block list. Unblock takes it off. Fixture results only. This build does not call Cloudflare.",
    status: "available",
    capabilities: ["response"],
    remotePermissions: [
      "Account API token limited to one WAF custom list",
      "Account API token limited to one Zero Trust Gateway block list",
    ],
    config: z.object({
      accountId: z.string().min(1),
      listName: z.string().min(1).default("blaksoc-block"),
      mode: z.enum(["fixture", "live"]).default("fixture"),
    }),
    secrets: z.object({ apiToken: z.string().min(1) }),
    create: (c, s) => ({ kind: "events", provider: new CloudflareProvider(c as never, s as never) }),
  },
  {
    provider: "sophos",
    name: "Sophos Central",
    category: "endpoint",
    description: "Isolates an endpoint, runs an antivirus scan, and blocks an indicator on the firewall host group. Release and unblock undo those steps. Fixture results only. This build does not call Sophos.",
    status: "available",
    capabilities: ["events", "assets", "response"],
    remotePermissions: ["Sophos Central endpoint isolation", "Sophos Central endpoint scan", "Sophos firewall host group edit"],
    config: z.object({
      centralId: z.string().min(1),
      region: z.string().min(1).default("au"),
      mode: z.enum(["fixture", "live"]).default("fixture"),
    }),
    secrets: z.object({ clientId: z.string().min(1), clientSecret: z.string().min(1) }),
    create: (c, s) => ({ kind: "events", provider: new SophosProvider(c as never, s as never) }),
  },
  planned("cisco", "Cisco", "network", ["response"], "Secure Firewall / Umbrella blocking."),
  planned("aws", "AWS", "cloud", ["events", "assets"], "GuardDuty, Security Hub, inventory."),
  planned("azure", "Azure", "cloud", ["events", "assets"], "Defender for Cloud, Resource Graph inventory."),
  planned("gcp", "Google Cloud", "cloud", ["events", "assets"], "Security Command Center."),
  {
    provider: "sms",
    name: "SMS (MessageMedia)",
    category: "collaboration",
    description: "Texts an Australian mobile via MessageMedia. Fixture mode records delivery and does not call MessageMedia.",
    status: "available",
    capabilities: ["notify"],
    remotePermissions: ["MessageMedia API key and secret on an Australian account"],
    config: z.object({
      from: z.string().regex(/^\+61\d{8,10}$/),
      mode: z.enum(["fixture", "live"]).default("fixture"),
      events: z.array(z.string()).default(["incident.created"]),
    }),
    secrets: z.object({ apiKey: z.string().min(1), apiSecret: z.string().min(1) }),
    create: (c, s) => ({
      kind: "notify",
      provider: new SmsNotifier(
        { from: String(c.from), mode: c.mode === "live" ? "live" : "fixture" },
        { apiKey: String(s.apiKey), apiSecret: String(s.apiSecret) },
      ),
    }),
  },
  {
    provider: "voice",
    name: "Voice call (Twilio AU)",
    category: "collaboration",
    description: "Rings an Australian number and speaks the update via Twilio. Fixture mode records delivery and does not call Twilio.",
    status: "available",
    capabilities: ["notify"],
    remotePermissions: ["Twilio Account SID, auth token, and an Australian +61 voice number"],
    config: z.object({
      from: z.string().regex(/^\+61\d{8,10}$/),
      mode: z.enum(["fixture", "live"]).default("fixture"),
      events: z.array(z.string()).default(["incident.created"]),
    }),
    secrets: z.object({ accountSid: z.string().min(1), authToken: z.string().min(1) }),
    create: (c, s) => ({
      kind: "notify",
      provider: new VoiceNotifier(
        { from: String(c.from), mode: c.mode === "live" ? "live" : "fixture" },
        { accountSid: String(s.accountSid), authToken: String(s.authToken) },
      ),
    }),
  },
  {
    provider: "email",
    name: "Email (SMTP)",
    category: "collaboration",
    description: "Sends the incident update through an SMTP relay. Fixture mode records delivery without opening a socket.",
    status: "available",
    capabilities: ["notify"],
    remotePermissions: ["SMTP username and password for the relay"],
    config: z.object({
      host: z.string().min(1),
      port: z.number().int().min(1).max(65535).default(587),
      from: z.string().email(),
      mode: z.enum(["fixture", "live"]).default("fixture"),
      events: z.array(z.string()).default(["incident.created"]),
    }),
    secrets: z.object({ username: z.string().min(1), password: z.string().min(1) }),
    create: (c, s) => ({
      kind: "notify",
      provider: new EmailNotifier(
        { host: String(c.host), port: Number(c.port), from: String(c.from), mode: c.mode === "live" ? "live" : "fixture" },
        { username: String(s.username), password: String(s.password) },
      ),
    }),
  },
  planned("jira", "Jira", "ticketing", ["ticket"], "Incident ↔ issue sync."),
  planned("servicenow", "ServiceNow", "ticketing", ["ticket"], "Security incident ↔ SIR sync."),
];

export function connectorDef(provider: string): ConnectorDefinition | undefined {
  return CONNECTORS.find((c) => c.provider === provider);
}

function aiConnectors(): ConnectorDefinition[] {
  const residency = {
    /** Declared by the admin; checked against AI_DATA_RESIDENCY policy. */
    region: z.string().min(2),
    country: z.string().length(2).default("AU"),
  };
  const oai = (provider: string, name: string, description: string, selfHosted: boolean, needsKey: boolean, azure = false): ConnectorDefinition => ({
    provider, name, description, category: "ai", status: "available", capabilities: ["inference"], remotePermissions: [],
    config: z.object({ baseUrl: z.string().url(), model: z.string().min(1), ...(azure ? { apiVersion: z.string().default("2024-10-21") } : {}), ...residency }),
    secrets: needsKey ? z.object({ apiKey: z.string().min(1) }) : z.object({ apiKey: z.string().optional() }) as never,
    create: (c, s) => ({
      kind: "ai",
      provider: new OpenAICompatibleProvider(provider, {
        baseUrl: c.baseUrl as string, model: c.model as string, apiKey: s.apiKey, azureApiVersion: azure ? (c.apiVersion as string) : undefined,
        residency: { region: c.region as string, country: c.country as string, selfHosted },
      }),
    }),
  });
  return [
    oai("ollama", "Ollama (local)", "Self-hosted models on blakSOC infrastructure. Data never leaves the deployment.", true, false),
    oai("vllm", "vLLM (local)", "Self-hosted OpenAI-compatible inference server.", true, false),
    oai("azure-openai", "Azure OpenAI", "Azure OpenAI deployment. Use Australia East for AU residency.", false, true, true),
    oai("openai-compatible", "OpenAI-compatible API", "Any OpenAI-compatible endpoint. Declare its processing region honestly.", false, true),
    {
      provider: "bedrock", name: "Amazon Bedrock", category: "ai", status: "available", capabilities: ["inference"],
      description: "Bedrock Converse API. ap-southeast-2 (Sydney) or ap-southeast-4 (Melbourne) for AU residency; avoid cross-region inference profiles.",
      remotePermissions: ["bedrock:InvokeModel on the chosen model ARN"],
      config: z.object({ region: z.string().min(1), model: z.string().min(1) }),
      secrets: z.object({ accessKeyId: z.string().optional(), secretAccessKey: z.string().optional() }) as never,
      create: (c, s) => ({ kind: "ai", provider: new BedrockProvider("bedrock", { region: c.region as string, model: c.model as string, accessKeyId: s.accessKeyId, secretAccessKey: s.secretAccessKey }) }),
    },
  ];
}
