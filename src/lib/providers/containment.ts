import { holdAction, refuseLive, releaseAction } from "@/lib/providers/fixture-action";
import type {
  AlertQuery,
  NormalisedAlert,
  NormalisedAsset,
  NormalisedVulnerability,
  ProviderHealth,
  ResponseActionRequest,
  ResponseActionResult,
  SecurityEventProvider,
} from "@/lib/providers/types";

const SEEN = new Date("2026-01-15T00:00:00.000Z");

export type DefenderConfig = { tenantDomain: string; mode: "fixture" | "live" };
export type DefenderSecrets = { clientId: string; clientSecret: string };
export type CloudflareConfig = { accountId: string; listName: string; mode: "fixture" | "live" };
export type CloudflareSecrets = { apiToken: string };
export type FortinetConfig = { host: string; addressGroup: string; mode: "fixture" | "live" };
export type FortinetSecrets = { apiToken: string };
export type SophosConfig = { centralId: string; region: string; mode: "fixture" | "live" };
export type SophosSecrets = { clientId: string; clientSecret: string };

function fixtureAlert(kind: string, title: string, assetExternalId: string): NormalisedAlert {
  return {
    externalId: `${kind}:fixture-incident`,
    ruleId: `${kind}.fixture`,
    title,
    description: null,
    category: "incident",
    siemSeverity: null,
    severity: "high",
    occurredAt: SEEN,
    assetExternalId,
    hostname: "fixture-endpoint",
    userName: null,
    attackTechniques: [],
    routingKeys: [],
    raw: { fixture: true, kind },
  };
}

function fixtureEndpoint(externalId: string): NormalisedAsset {
  return {
    externalId,
    kind: "endpoint",
    name: "fixture-endpoint",
    hostname: "fixture-endpoint",
    ips: ["10.26.0.11"],
    os: "Windows 11",
    macs: [],
    agentStatus: "active",
    lastSeen: SEEN,
    routingKeys: [],
    raw: { fixture: true },
  };
}

function indicatorOf(req: ResponseActionRequest): string {
  const raw = req.params?.indicator ?? req.params?.srcip ?? req.assetExternalId;
  return typeof raw === "string" ? raw.trim() : "";
}

/** Shared fixture surface. Subclasses add the actions that vendor actually supports. */
abstract class FixtureContainment implements SecurityEventProvider {
  abstract readonly kind: string;
  protected abstract readonly product: string;
  protected abstract readonly scope: string;
  protected abstract readonly mode: "fixture" | "live";
  protected abstract readonly credential: boolean;

  protected guard(): void {
    refuseLive(this.mode, this.product);
  }

  async getAlerts(_q: AlertQuery): Promise<{ alerts: NormalisedAlert[]; cursor: string | null }> {
    this.guard();
    return { alerts: [], cursor: null };
  }

  async getAlert(externalId: string): Promise<NormalisedAlert | null> {
    const { alerts } = await this.getAlerts({});
    return alerts.find((row) => row.externalId === externalId) ?? null;
  }

  async searchEvents(q: AlertQuery): Promise<{ total: number; events: Record<string, unknown>[] }> {
    const { alerts } = await this.getAlerts(q);
    return { total: alerts.length, events: alerts.map((row) => row.raw) };
  }

  async getAssets(): Promise<NormalisedAsset[]> {
    this.guard();
    return [];
  }

  async getAsset(externalId: string): Promise<NormalisedAsset | null> {
    return (await this.getAssets()).find((row) => row.externalId === externalId) ?? null;
  }

  abstract supportedActions(): ResponseActionRequest["action"][];
  abstract executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult>;

  async health(): Promise<ProviderHealth> {
    const start = Date.now();
    try {
      this.guard();
      return { ok: true, latencyMs: Date.now() - start, detail: { mode: this.mode, scope: this.scope, credential: this.credential } };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - start, detail: { mode: this.mode }, error: (err as Error).message };
    }
  }
}

export class DefenderProvider extends FixtureContainment {
  readonly kind = "defender";
  protected readonly product = "Defender";
  protected readonly scope: string;
  protected readonly mode: "fixture" | "live";
  protected readonly credential: boolean;
  private readonly alert = fixtureAlert("defender", "Defender fixture incident", "device-1");
  private readonly asset = fixtureEndpoint("device-1");

  constructor(config: DefenderConfig, secrets: DefenderSecrets) {
    super();
    this.scope = config.tenantDomain;
    this.mode = config.mode;
    this.credential = Boolean(secrets.clientId && secrets.clientSecret);
  }

  supportedActions(): ResponseActionRequest["action"][] {
    return ["isolate_endpoint", "release_endpoint", "scan_endpoint"];
  }

  async getAlerts(_q: AlertQuery): Promise<{ alerts: NormalisedAlert[]; cursor: string | null }> {
    this.guard();
    return { alerts: [this.alert], cursor: null };
  }

  async getAssets(): Promise<NormalisedAsset[]> {
    this.guard();
    return [this.asset];
  }

  async getVulnerabilities(): Promise<NormalisedVulnerability[]> {
    this.guard();
    return [{
      assetExternalId: "device-1",
      cve: "CVE-2099-1001",
      title: "Defender fixture vulnerability",
      packageName: null,
      packageVersion: null,
      fixedVersion: null,
      cvss: 7.5,
    }];
  }

  async executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult> {
    this.guard();
    if (req.action === "isolate_endpoint") return holdAction(this.kind, this.scope, "isolate", req.assetExternalId, "isolated");
    if (req.action === "release_endpoint") return releaseAction(this.kind, this.scope, "isolate", req.assetExternalId);
    if (req.action === "scan_endpoint") return holdAction(this.kind, this.scope, "scan", req.assetExternalId, "scanned");
    return { ok: false, message: `${this.kind} does not support ${req.action}` };
  }
}

export class CloudflareProvider extends FixtureContainment {
  readonly kind = "cloudflare";
  protected readonly product = "Cloudflare";
  protected readonly scope: string;
  protected readonly mode: "fixture" | "live";
  protected readonly credential: boolean;

  constructor(config: CloudflareConfig, secrets: CloudflareSecrets) {
    super();
    this.scope = `${config.accountId}:${config.listName}`;
    this.mode = config.mode;
    this.credential = Boolean(secrets.apiToken);
  }

  supportedActions(): ResponseActionRequest["action"][] {
    return ["block_ioc", "unblock_ioc"];
  }

  async executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult> {
    this.guard();
    return blockOrRelease(this.kind, this.scope, req);
  }
}

export class FortinetProvider extends FixtureContainment {
  readonly kind = "fortinet";
  protected readonly product = "FortiGate";
  protected readonly scope: string;
  protected readonly mode: "fixture" | "live";
  protected readonly credential: boolean;

  constructor(config: FortinetConfig, secrets: FortinetSecrets) {
    super();
    this.scope = `${config.host}:${config.addressGroup}`;
    this.mode = config.mode;
    this.credential = Boolean(secrets.apiToken);
  }

  supportedActions(): ResponseActionRequest["action"][] {
    return ["block_ioc", "unblock_ioc"];
  }

  async executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult> {
    this.guard();
    return blockOrRelease(this.kind, this.scope, req);
  }
}

export class SophosProvider extends FixtureContainment {
  readonly kind = "sophos";
  protected readonly product = "Sophos";
  protected readonly scope: string;
  protected readonly mode: "fixture" | "live";
  protected readonly credential: boolean;
  private readonly alert = fixtureAlert("sophos", "Sophos fixture alert", "sophos-endpoint-1");
  private readonly asset = fixtureEndpoint("sophos-endpoint-1");

  constructor(config: SophosConfig, secrets: SophosSecrets) {
    super();
    this.scope = config.centralId;
    this.mode = config.mode;
    this.credential = Boolean(secrets.clientId && secrets.clientSecret);
  }

  supportedActions(): ResponseActionRequest["action"][] {
    return ["isolate_endpoint", "release_endpoint", "scan_endpoint", "block_ioc", "unblock_ioc"];
  }

  async getAlerts(_q: AlertQuery): Promise<{ alerts: NormalisedAlert[]; cursor: string | null }> {
    this.guard();
    return { alerts: [this.alert], cursor: null };
  }

  async getAssets(): Promise<NormalisedAsset[]> {
    this.guard();
    return [this.asset];
  }

  async executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult> {
    this.guard();
    if (req.action === "isolate_endpoint") return holdAction(this.kind, this.scope, "isolate", req.assetExternalId, "isolated");
    if (req.action === "release_endpoint") return releaseAction(this.kind, this.scope, "isolate", req.assetExternalId);
    if (req.action === "scan_endpoint") return holdAction(this.kind, this.scope, "scan", req.assetExternalId, "scanned");
    if (req.action === "block_ioc" || req.action === "unblock_ioc") return blockOrRelease(this.kind, this.scope, req);
    return { ok: false, message: `${this.kind} does not support ${req.action}` };
  }
}

function blockOrRelease(kind: string, scope: string, req: ResponseActionRequest): ResponseActionResult {
  const indicator = indicatorOf(req);
  if (!indicator) return { ok: false, message: `${req.action} needs an indicator` };
  if (req.action === "block_ioc") return holdAction(kind, scope, "block", indicator, "blocked");
  if (req.action === "unblock_ioc") return releaseAction(kind, scope, "block", indicator);
  return { ok: false, message: `${kind} does not support ${req.action}` };
}
