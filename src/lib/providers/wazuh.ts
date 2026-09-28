import { httpJson, type HttpOptions } from "./http";
import type {
  AlertQuery, NormalisedAlert, NormalisedAsset, NormalisedVulnerability, ProviderHealth, ResponseActionRequest,
  ResponseActionResult, SecurityEventProvider, Severity,
} from "./types";

export type WazuhConfig = {
  apiUrl: string; // https://wazuh-manager:55000
  indexerUrl: string; // https://wazuh-indexer:9200
  alertsIndex?: string; // default wazuh-alerts-4.x-*
  vulnerabilitiesIndex?: string; // default wazuh-states-vulnerabilities-*
  tlsVerify?: boolean;
  caPem?: string;
  /**
   * Active-response command names configured on the manager. Wazuh has no native
   * isolation; blakSOC ships scripts in deploy/wazuh/active-response. A value may be
   * per-platform, e.g. { windows: "blaksoc-isolate-win", default: "blaksoc-isolate" }.
   */
  activeResponse?: Partial<Record<ResponseActionRequest["action"], string | { windows?: string; default: string }>>;
};

export type WazuhSecrets = { apiUser: string; apiPassword: string; indexerUser: string; indexerPassword: string };

type ArCommand = string | { windows?: string; default: string };

const DEFAULT_AR: Partial<Record<ResponseActionRequest["action"], ArCommand>> = {
  isolate_endpoint: { windows: "blaksoc-isolate-win", default: "blaksoc-isolate" },
  release_endpoint: { windows: "blaksoc-release-win", default: "blaksoc-release" },
  block_ip: { windows: "netsh", default: "firewall-drop" },
};

function resolveCommand(c: ArCommand | undefined, platform: string | undefined): string | undefined {
  if (!c || typeof c === "string") return c;
  return platform === "windows" && c.windows ? c.windows : c.default;
}

/** Wazuh rule level (0–15) to blakSOC severity. */
export function wazuhLevelToSeverity(level: number): Severity {
  if (level >= 13) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  if (level >= 4) return "low";
  return "informational";
}

type WazuhAlertSource = {
  timestamp: string;
  id?: string;
  rule?: { id?: string; level?: number; description?: string; groups?: string[]; mitre?: { id?: string[] } };
  agent?: { id?: string; name?: string; ip?: string };
  data?: Record<string, unknown> & { srcuser?: string; dstuser?: string; win?: { eventdata?: Record<string, unknown> } };
  full_log?: string;
};

export function normaliseWazuhAlert(id: string, src: WazuhAlertSource): NormalisedAlert {
  const level = src.rule?.level ?? 0;
  const eventdata = src.data?.win?.eventdata ?? {};
  const user =
    (src.data?.dstuser as string | undefined) ??
    (src.data?.srcuser as string | undefined) ??
    (eventdata.targetUserName as string | undefined) ??
    (eventdata.subjectUserName as string | undefined) ??
    null;
  return {
    externalId: id,
    ruleId: src.rule?.id ?? null,
    title: src.rule?.description ?? "Wazuh alert",
    description: src.full_log ?? null,
    category: src.rule?.groups?.[0] ?? null,
    siemSeverity: level,
    severity: wazuhLevelToSeverity(level),
    occurredAt: new Date(src.timestamp),
    assetExternalId: src.agent?.id && src.agent.id !== "000" ? src.agent.id : null,
    hostname: src.agent?.name ?? null,
    userName: user,
    attackTechniques: src.rule?.mitre?.id ?? [],
    routingKeys: src.agent?.id ? [`agent:${src.agent.id}`] : [],
    raw: src as Record<string, unknown>,
  };
}

type WazuhAgent = {
  id: string;
  name: string;
  ip?: string;
  status?: string;
  group?: string[];
  lastKeepAlive?: string;
  os?: { name?: string; version?: string; platform?: string };
};

function normaliseAgent(a: WazuhAgent): NormalisedAsset {
  const osName = [a.os?.name, a.os?.version].filter(Boolean).join(" ") || null;
  const server = /server/i.test(osName ?? "") || a.os?.platform === "ubuntu" || a.os?.platform === "rhel";
  return {
    externalId: a.id,
    kind: server ? "server" : "endpoint",
    name: a.name,
    hostname: a.name,
    ips: a.ip && a.ip !== "any" ? [a.ip] : [],
    os: osName,
    macs: [],
    agentStatus: a.status ?? null,
    lastSeen: a.lastKeepAlive ? new Date(a.lastKeepAlive) : null,
    routingKeys: (a.group ?? []).map((g) => `group:${g}`),
    raw: a as unknown as Record<string, unknown>,
  };
}

export class WazuhProvider implements SecurityEventProvider {
  readonly kind = "wazuh";
  private token: { value: string; expires: number } | null = null;
  private readonly http: HttpOptions;

  constructor(private readonly cfg: WazuhConfig, private readonly secrets: WazuhSecrets) {
    this.http = { tlsVerify: cfg.tlsVerify, caPem: cfg.caPem };
  }

  private async apiToken(): Promise<string> {
    if (this.token && this.token.expires > Date.now()) return this.token.value;
    const basic = Buffer.from(`${this.secrets.apiUser}:${this.secrets.apiPassword}`).toString("base64");
    const res = await httpJson<{ data: { token: string } }>(
      `${this.cfg.apiUrl}/security/user/authenticate`,
      { method: "POST", headers: { authorization: `Basic ${basic}` } },
      this.http,
    );
    // Wazuh tokens default to 900s; refresh early.
    this.token = { value: res.data.token, expires: Date.now() + 12 * 60_000 };
    return this.token.value;
  }

  private async api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
    const token = await this.apiToken();
    return httpJson<T>(`${this.cfg.apiUrl}${path}`, { ...init, headers: { authorization: `Bearer ${token}`, ...init.headers } }, this.http);
  }

  private async search<T>(index: string, body: unknown): Promise<T> {
    const basic = Buffer.from(`${this.secrets.indexerUser}:${this.secrets.indexerPassword}`).toString("base64");
    return httpJson<T>(`${this.cfg.indexerUrl}/${index}/_search`, { method: "POST", json: body, headers: { authorization: `Basic ${basic}` } }, this.http);
  }

  private alertsQuery(q: AlertQuery) {
    const filter: unknown[] = [
      { range: { timestamp: { gte: (q.since ?? new Date(Date.now() - 3600_000)).toISOString(), lte: (q.until ?? new Date()).toISOString() } } },
    ];
    const agentIds = (q.routingKeys ?? []).filter((k) => k.startsWith("agent:")).map((k) => k.slice(6));
    if (agentIds.length) filter.push({ terms: { "agent.id": agentIds } });
    if (q.query) filter.push({ query_string: { query: q.query, analyze_wildcard: true } });
    return { bool: { filter } };
  }

  async getAlerts(q: AlertQuery) {
    type Hit = { _id: string; _source: WazuhAlertSource; sort: unknown[] };
    const res = await this.search<{ hits: { hits: Hit[] } }>(this.cfg.alertsIndex ?? "wazuh-alerts-4.x-*", {
      size: Math.min(q.limit ?? 500, 1000),
      sort: [{ timestamp: "asc" }, { _id: "asc" }],
      query: this.alertsQuery(q),
      ...(q.afterCursor ? { search_after: JSON.parse(Buffer.from(q.afterCursor, "base64url").toString()) } : {}),
    });
    const hits = res.hits.hits;
    const last = hits.at(-1);
    return {
      alerts: hits.map((h) => normaliseWazuhAlert(h._id, h._source)),
      cursor: last ? Buffer.from(JSON.stringify(last.sort)).toString("base64url") : null,
    };
  }

  async getAlert(externalId: string) {
    type Hit = { _id: string; _source: WazuhAlertSource };
    const res = await this.search<{ hits: { hits: Hit[] } }>(this.cfg.alertsIndex ?? "wazuh-alerts-4.x-*", {
      size: 1,
      query: { ids: { values: [externalId] } },
    });
    const h = res.hits.hits[0];
    return h ? normaliseWazuhAlert(h._id, h._source) : null;
  }

  async searchEvents(q: AlertQuery) {
    const res = await this.search<{ hits: { total: { value: number }; hits: { _id: string; _source: Record<string, unknown> }[] } }>(
      this.cfg.alertsIndex ?? "wazuh-alerts-4.x-*",
      { size: Math.min(q.limit ?? 100, 500), sort: [{ timestamp: "desc" }], query: this.alertsQuery(q), track_total_hits: true },
    );
    return { total: res.hits.total.value, events: res.hits.hits.map((h) => ({ _id: h._id, ...h._source })) };
  }

  async getAssets(routingKeys?: string[]) {
    const groups = (routingKeys ?? []).filter((k) => k.startsWith("group:")).map((k) => k.slice(6));
    const out: NormalisedAsset[] = [];
    for (let offset = 0; ; offset += 500) {
      const qs = new URLSearchParams({ limit: "500", offset: String(offset), select: "id,name,ip,status,group,lastKeepAlive,os" });
      if (groups.length === 1) qs.set("group", groups[0]!);
      const res = await this.api<{ data: { affected_items: WazuhAgent[]; total_affected_items: number } }>(`/agents?${qs}`);
      out.push(...res.data.affected_items.filter((a) => a.id !== "000").map(normaliseAgent));
      if (offset + 500 >= res.data.total_affected_items) break;
    }
    return groups.length > 1 ? out.filter((a) => a.routingKeys.some((k) => routingKeys!.includes(k))) : out;
  }

  async getAsset(externalId: string) {
    const res = await this.api<{ data: { affected_items: WazuhAgent[] } }>(`/agents?agents_list=${encodeURIComponent(externalId)}`);
    const a = res.data.affected_items[0];
    return a ? normaliseAgent(a) : null;
  }

  async getVulnerabilities(assetExternalIds?: string[]): Promise<NormalisedVulnerability[]> {
    type Src = {
      agent?: { id?: string };
      vulnerability?: { id?: string; description?: string; score?: { base?: number } };
      package?: { name?: string; version?: string };
    };
    const res = await this.search<{ hits: { hits: { _source: Src }[] } }>(this.cfg.vulnerabilitiesIndex ?? "wazuh-states-vulnerabilities-*", {
      size: 5000,
      query: assetExternalIds?.length ? { terms: { "agent.id": assetExternalIds } } : { match_all: {} },
    });
    return res.hits.hits
      .map((h) => h._source)
      .filter((s) => s.agent?.id && s.vulnerability?.id)
      .map((s) => ({
        assetExternalId: s.agent!.id!,
        cve: s.vulnerability!.id!,
        title: s.vulnerability?.description?.slice(0, 300) ?? null,
        packageName: s.package?.name ?? null,
        packageVersion: s.package?.version ?? null,
        fixedVersion: null,
        cvss: s.vulnerability?.score?.base ?? null,
      }));
  }

  supportedActions(): ResponseActionRequest["action"][] {
    const ar = { ...DEFAULT_AR, ...this.cfg.activeResponse };
    return (Object.keys(ar) as ResponseActionRequest["action"][]).filter((k) => ar[k]);
  }

  async executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult> {
    const command = resolveCommand({ ...DEFAULT_AR, ...this.cfg.activeResponse }[req.action], req.params?.platform as string | undefined);
    if (!command) return { ok: false, message: `action ${req.action} not configured for this Wazuh cluster` };
    const args = Array.isArray(req.params?.arguments) ? (req.params!.arguments as string[]) : [];
    const alert = req.params?.srcip ? { data: { srcip: String(req.params.srcip) } } : undefined;
    const res = await this.api<{ data: { total_affected_items: number; failed_items?: unknown[] }; message?: string }>(
      `/active-response?agents_list=${encodeURIComponent(req.assetExternalId)}`,
      { method: "PUT", json: { command, arguments: args, ...(alert ? { alert } : {}) } },
    );
    const ok = res.data.total_affected_items > 0;
    return { ok, message: res.message ?? (ok ? "active response dispatched" : "no agents affected") };
  }

  async health(): Promise<ProviderHealth> {
    const start = Date.now();
    try {
      const [info, agents] = await Promise.all([
        this.api<{ data: { api_version?: string; hostname?: string } }>("/"),
        this.api<{ data: { connection?: Record<string, number> } }>("/agents/summary/status"),
      ]);
      return { ok: true, latencyMs: Date.now() - start, detail: { version: info.data.api_version, host: info.data.hostname, agents: agents.data.connection } };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - start, detail: {}, error: (err as Error).message };
    }
  }
}
