import type { NormalisedAlert, Severity } from "@/lib/providers/types";

export const SYSLOG_VENDORS = ["fortinet", "sophos", "draytek", "mikrotik", "ubiquiti"] as const;
export type SyslogVendor = (typeof SYSLOG_VENDORS)[number];

const LABEL: Record<SyslogVendor, string> = {
  fortinet: "FortiGate",
  sophos: "Sophos",
  draytek: "DrayTek",
  mikrotik: "MikroTik",
  ubiquiti: "UniFi",
};

const IP = "(?:\\d{1,3}\\.){3}\\d{1,3}";

export type ParsedSyslog = {
  vendor: SyslogVendor;
  action: string;
  srcIp: string | null;
  dstIp: string | null;
  srcPort: number | null;
  dstPort: number | null;
  proto: string | null;
  user: string | null;
  hostname: string | null;
  occurredAt: Date | null;
  severity: Severity;
  title: string;
};

function field(line: string, name: string): string | null {
  const quoted = line.match(new RegExp(`\\b${name}="([^"]*)"`, "i"));
  if (quoted) return quoted[1] ?? null;
  const bare = line.match(new RegExp(`\\b${name}=([^\\s]+)`, "i"));
  return bare?.[1] ?? null;
}

function portOf(value: string | null | undefined): number | null {
  if (!value || !/^\d+$/.test(value)) return null;
  const n = Number(value);
  return n >= 0 && n <= 65535 ? n : null;
}

function protoName(value: string | null): string | null {
  if (!value) return null;
  if (value === "6") return "TCP";
  if (value === "17") return "UDP";
  if (value === "1") return "ICMP";
  return value.toUpperCase();
}

function vendorOf(line: string): SyslogVendor | null {
  if (/\bdevname=/.test(line) && /\bsrcip=/.test(line)) return "fortinet";
  if (/\blog_type=/.test(line) || /\blog_subtype=/.test(line)) return "sophos";
  if (/draytek/i.test(line) || /\[FILTER\]/.test(line) || /\[DoS\]/.test(line)) return "draytek";
  if (/mikrotik/i.test(line) || /firewall,info/.test(line)) return "mikrotik";
  if (/\bubnt\b/i.test(line) || /unifi/i.test(line) || /\bWAN_IN\b/.test(line) || /\bUDM/.test(line)) return "ubiquiti";
  return null;
}

function severityFor(action: string, line: string): Severity {
  const blob = `${action} ${line}`.toLowerCase();
  if (/malware|exploit|critical/.test(blob)) return "critical";
  if (/ips|attack|dos|flood|intrusion|anomaly/.test(blob)) return "high";
  if (/deny|denied|drop|dropped|block|blocked|reject/.test(blob)) return "medium";
  return "informational";
}

function occurredAtOf(line: string): Date | null {
  const date = field(line, "date");
  const time = field(line, "time");
  if (date && time) {
    const at = new Date(`${date}T${time}Z`);
    if (!Number.isNaN(at.getTime())) return at;
  }
  const iso = line.match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/);
  if (!iso) return null;
  const at = new Date(iso[0]);
  return Number.isNaN(at.getTime()) ? null : at;
}

function endpoint(line: string, name: string): { ip: string | null; port: number | null } {
  const match = line.match(new RegExp(`\\b${name}=(${IP})(?::(\\d+))?`, "i"));
  return { ip: match?.[1] ?? null, port: portOf(match?.[2]) };
}

/** One vendor line to structured fields. Unknown shapes return null. */
export function parseSyslog(line: string): ParsedSyslog | null {
  const vendor = vendorOf(line);
  if (!vendor) return null;
  const action = (field(line, "action") ?? field(line, "log_subtype") ?? (/\bBLOCK\b/.test(line) ? "blocked" : vendor === "ubiquiti" && /\bWAN_IN\b/.test(line) ? "blocked" : "observed")).toLowerCase();
  const src = endpoint(line, "src");
  const dst = endpoint(line, "dst");
  const srcIp = field(line, "srcip") ?? field(line, "src_ip") ?? src.ip;
  const dstIp = field(line, "dstip") ?? field(line, "dst_ip") ?? dst.ip;
  const srcPort = portOf(field(line, "srcport") ?? field(line, "src_port") ?? field(line, "sport") ?? field(line, "SPT")) ?? src.port;
  const dstPort = portOf(field(line, "dstport") ?? field(line, "dst_port") ?? field(line, "dport") ?? field(line, "DPT")) ?? dst.port;
  const hostname = field(line, "devname") ?? field(line, "device_name") ?? line.match(/\b(UDM[A-Za-z0-9-]*|USG[A-Za-z0-9-]*)\b/)?.[1] ?? (vendor === "draytek" ? "DrayTek" : vendor === "mikrotik" ? "MikroTik" : null);
  return {
    vendor,
    action,
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    proto: protoName(field(line, "proto") ?? field(line, "protocol") ?? field(line, "PROTO")),
    user: field(line, "user") ?? field(line, "user_name"),
    hostname,
    occurredAt: occurredAtOf(line),
    severity: severityFor(action, line),
    title: `${LABEL[vendor]} ${action}`,
  };
}

/** The alert shape the syslog provider returns to the ingest pipeline. */
export function normaliseSyslog(row: { id: string; line: string; byteLen: number; ingestedAt: Date }, tenantId: string): NormalisedAlert | null {
  const parsed = parseSyslog(row.line);
  if (!parsed) return null;
  return {
    externalId: row.id,
    ruleId: `${parsed.vendor}:${parsed.action}`,
    title: parsed.title,
    description: null,
    category: "network",
    siemSeverity: null,
    severity: parsed.severity,
    occurredAt: parsed.occurredAt ?? row.ingestedAt,
    assetExternalId: null,
    hostname: parsed.hostname,
    userName: parsed.user,
    attackTechniques: [],
    routingKeys: [`tenant:${tenantId}`],
    raw: {
      line: row.line,
      vendor: parsed.vendor,
      action: parsed.action,
      srcIp: parsed.srcIp,
      dstIp: parsed.dstIp,
      srcPort: parsed.srcPort,
      dstPort: parsed.dstPort,
      proto: parsed.proto,
      bytes: row.byteLen,
    },
  };
}
