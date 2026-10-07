import type { Observable } from "@/lib/intel/observables";
import type { NormalisedAlert, NormalisedVulnerability, Severity } from "@/lib/providers/types";
import {
  ACTION_ID, ANALYTIC_TYPE_ID, AUTH_ACTIVITY, AUTH_PROTOCOL_ID, DISPOSITION_ID, FINDING_ACTIVITY, FINDING_STATUS, NETWORK_ACTIVITY,
  NORMALIZATION_VERSION, OBSERVABLE_TYPE_ID, OCSF_CLASSES, OCSF_VERSION, SEVERITY_ID, SEVERITY_NAME, STATUS_ID,
  type Authentication, type DetectionFinding, type NetworkActivity, type OcsfAttack, type OcsfBase, type OcsfClassKey, type OcsfEvidence,
  type OcsfMetadata, type OcsfObservable, type OcsfProduct, type VulnerabilityFinding,
} from "./schema";

/** Where an event came from and when blakSOC received it. Becomes OCSF metadata. */
export type Provenance = {
  /** blakSOC source key, e.g. `wazuh`, `entra`, `syslog`. Stored as metadata.log_name. */
  source: string;
  /** The source system's id for the record (alerts.external_id). */
  sourceEventId: string;
  tenantId: string;
  ingestedAt: Date;
  /** When the mapper ran. Defaults to now. */
  processedAt?: Date;
};

const PRODUCTS: Record<string, OcsfProduct> = {
  wazuh: { name: "Wazuh", vendor_name: "Wazuh" },
  tawny: { name: "Tawny EDR", vendor_name: "Yuma IT" },
  entra: { name: "Microsoft Entra ID", vendor_name: "Microsoft" },
  m365: { name: "Microsoft 365", vendor_name: "Microsoft" },
  "google-workspace": { name: "Google Workspace", vendor_name: "Google" },
  syslog: { name: "Syslog", vendor_name: "blakSOC" },
  "blaksoc-sigma": { name: "blakSOC Sigma detections", vendor_name: "Yuma IT" },
  "blaksoc-correlation": { name: "blakSOC correlation engine", vendor_name: "Yuma IT" },
  asm: { name: "blakSOC attack surface", vendor_name: "Yuma IT" },
  "credential-exposure": { name: "blakSOC credential exposure", vendor_name: "Yuma IT" },
  demo: { name: "blakSOC demo provider", vendor_name: "Yuma IT" },
};

/** Syslog firewall vendors as parsed by src/lib/syslog/parse.ts. */
const SYSLOG_VENDORS: Record<string, string> = { fortinet: "Fortinet", sophos: "Sophos", draytek: "DrayTek", mikrotik: "MikroTik", ubiquiti: "Ubiquiti" };

export function productFor(source: string): OcsfProduct {
  return PRODUCTS[source] ?? { name: source };
}

export function severityId(severity: Severity): number {
  return SEVERITY_ID[severity];
}

function classFields(key: OcsfClassKey, activityId: number, activityName: string): Pick<OcsfBase, "class_uid" | "class_name" | "category_uid" | "category_name" | "activity_id" | "activity_name" | "type_uid"> {
  const c = OCSF_CLASSES[key];
  return { class_uid: c.class_uid, class_name: c.class_name, category_uid: c.category_uid, category_name: c.category_name, activity_id: activityId, activity_name: activityName, type_uid: c.class_uid * 100 + activityId };
}

export function ocsfMetadata(p: Provenance, product: OcsfProduct = productFor(p.source)): OcsfMetadata {
  const processed = (p.processedAt ?? new Date()).getTime();
  return {
    version: OCSF_VERSION,
    product,
    original_event_uid: p.sourceEventId,
    tenant_uid: p.tenantId,
    log_name: p.source,
    logged_time: p.ingestedAt.getTime(),
    processed_time: processed,
    transformation_info_list: [{ name: "blakSOC OCSF mapper", uid: NORMALIZATION_VERSION, time: processed }],
  };
}

const OBSERVABLE_TYPES: Record<Observable["type"], { id: number; name: string }> = {
  ipv4: { id: OBSERVABLE_TYPE_ID.ip_address, name: "IP Address" },
  ipv6: { id: OBSERVABLE_TYPE_ID.ip_address, name: "IP Address" },
  domain: { id: OBSERVABLE_TYPE_ID.hostname, name: "Hostname" },
  hostname: { id: OBSERVABLE_TYPE_ID.hostname, name: "Hostname" },
  url: { id: OBSERVABLE_TYPE_ID.url_string, name: "URL String" },
  md5: { id: OBSERVABLE_TYPE_ID.hash, name: "Hash" },
  sha1: { id: OBSERVABLE_TYPE_ID.hash, name: "Hash" },
  sha256: { id: OBSERVABLE_TYPE_ID.hash, name: "Hash" },
  email: { id: OBSERVABLE_TYPE_ID.email_address, name: "Email Address" },
  cve: { id: OBSERVABLE_TYPE_ID.cve, name: "CVE Object: uid" },
  user: { id: OBSERVABLE_TYPE_ID.user_name, name: "User Name" },
};

/** blakSOC observables as OCSF observables. `name` is the field the value was found in. */
export function ocsfObservables(obs: Observable[]): OcsfObservable[] {
  return obs.map((o) => ({ type_id: OBSERVABLE_TYPES[o.type].id, type: OBSERVABLE_TYPES[o.type].name, name: o.field ?? o.type, value: o.value }));
}

/** T1059.001 becomes technique T1059 with sub-technique T1059.001. Anything that is not a technique id is dropped. */
export function ocsfAttacks(techniques: string[]): OcsfAttack[] {
  const out: OcsfAttack[] = [];
  for (const id of new Set(techniques.map((t) => t.trim().toUpperCase()))) {
    const m = /^(T\d{4})(\.\d{3})?$/.exec(id);
    if (!m) continue;
    out.push(m[2] ? { technique: { uid: m[1]! }, sub_technique: { uid: id } } : { technique: { uid: id } });
  }
  return out;
}

function evidenceFor(alert: NormalisedAlert): OcsfEvidence[] | undefined {
  const evidence: OcsfEvidence = {};
  if (alert.hostname || alert.assetExternalId) evidence.device = { type_id: 0, ...(alert.hostname ? { hostname: alert.hostname } : {}), ...(alert.assetExternalId ? { uid: alert.assetExternalId } : {}) };
  if (alert.userName) evidence.user = { name: alert.userName };
  return Object.keys(evidence).length ? [evidence] : undefined;
}

/** Every alert, from any provider, as an OCSF Detection Finding (2004). */
export function toDetectionFinding(alert: NormalisedAlert, p: Provenance, extra: { observables?: Observable[]; riskScore?: number } = {}): DetectionFinding {
  const sev = severityId(alert.severity);
  const attacks = ocsfAttacks(alert.attackTechniques);
  const observables = extra.observables?.length ? ocsfObservables(extra.observables) : undefined;
  const evidences = evidenceFor(alert);
  return {
    ...classFields("detection_finding", FINDING_ACTIVITY.create, "Create"),
    class_uid: 2004,
    severity_id: sev,
    severity: SEVERITY_NAME[sev],
    time: alert.occurredAt.getTime(),
    message: alert.title,
    status_id: FINDING_STATUS.new,
    is_alert: true,
    ...(extra.riskScore !== undefined ? { risk_score: extra.riskScore } : {}),
    metadata: ocsfMetadata(p),
    finding_info: {
      uid: alert.externalId,
      title: alert.title,
      ...(alert.description ? { desc: alert.description } : {}),
      ...(alert.category ? { types: [alert.category] } : {}),
      ...(alert.ruleId ? { analytic: { type_id: ANALYTIC_TYPE_ID.rule, uid: alert.ruleId } } : {}),
      ...(attacks.length ? { attacks } : {}),
      created_time: alert.occurredAt.getTime(),
    },
    ...(evidences ? { evidences } : {}),
    ...(observables ? { observables } : {}),
    ...(alert.siemSeverity !== null ? { unmapped: { siem_severity: alert.siemSeverity } } : {}),
  };
}

const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : undefined);

/** A parsed firewall syslog line (alerts.raw from src/lib/syslog/parse.ts) as OCSF Network Activity (4001). */
export function syslogToNetworkActivity(alert: NormalisedAlert, p: Provenance): NetworkActivity | null {
  const raw = alert.raw;
  const srcIp = str(raw.srcIp);
  const dstIp = str(raw.dstIp);
  if (!srcIp && !dstIp) return null;
  const action = String(raw.action ?? "").toLowerCase();
  const denied = /deny|denied|drop|block|reject/.test(action);
  const allowed = /accept|allow|pass|permit|established/.test(action);
  const sev = severityId(alert.severity);
  const vendor = str(raw.vendor);
  return {
    ...classFields("network_activity", NETWORK_ACTIVITY.traffic, "Traffic"),
    class_uid: 4001,
    severity_id: sev,
    severity: SEVERITY_NAME[sev],
    time: alert.occurredAt.getTime(),
    message: alert.title,
    action_id: denied ? ACTION_ID.denied : allowed ? ACTION_ID.allowed : ACTION_ID.observed,
    disposition_id: denied ? DISPOSITION_ID.blocked : allowed ? DISPOSITION_ID.allowed : DISPOSITION_ID.unknown,
    metadata: ocsfMetadata(p, { name: "Syslog", vendor_name: (vendor && SYSLOG_VENDORS[vendor]) ?? vendor ?? "Unknown" }),
    ...(srcIp ? { src_endpoint: { ip: srcIp, ...(num(raw.srcPort) !== undefined ? { port: num(raw.srcPort) } : {}) } } : {}),
    ...(dstIp ? { dst_endpoint: { ip: dstIp, ...(num(raw.dstPort) !== undefined ? { port: num(raw.dstPort) } : {}) } } : {}),
    connection_info: { direction_id: 0, ...(str(raw.proto) ? { protocol_name: str(raw.proto)!.toLowerCase() } : {}) },
    ...(alert.hostname ? { device: { type_id: 9, hostname: alert.hostname } } : {}),
    unmapped: { action: raw.action ?? null },
  };
}

/** A Microsoft Entra sign-in record (Graph /auditLogs/signIns) as OCSF Authentication (3002). */
export function entraSignInToAuthentication(raw: Record<string, unknown>, p: Provenance): Authentication | null {
  const upn = str(raw.userPrincipalName);
  const userId = str(raw.userId);
  const at = str(raw.createdDateTime);
  const time = at ? Date.parse(at) : NaN;
  if ((!upn && !userId) || !Number.isFinite(time)) return null;
  const errorCode = Number((raw.status as { errorCode?: number } | undefined)?.errorCode ?? 0);
  const failureReason = str((raw.status as { failureReason?: string } | undefined)?.failureReason);
  const location = raw.location as { countryOrRegion?: string; city?: string; state?: string } | undefined;
  const requirement = String(raw.authenticationRequirement ?? "").toLowerCase();
  const protocol = String(raw.authenticationProtocol ?? "").toLowerCase();
  const protocolId = protocol.includes("saml") ? AUTH_PROTOCOL_ID.saml : protocol.includes("oauth") || protocol.includes("ropc") || protocol.includes("devicecode") ? AUTH_PROTOCOL_ID.oauth2 : protocol ? AUTH_PROTOCOL_ID.other : AUTH_PROTOCOL_ID.unknown;
  const failed = errorCode !== 0;
  const sev = failed ? SEVERITY_ID.low : SEVERITY_ID.informational;
  const ip = str(raw.ipAddress);
  const country = str(location?.countryOrRegion);
  return {
    ...classFields("authentication", AUTH_ACTIVITY.logon, "Logon"),
    class_uid: 3002,
    severity_id: sev,
    severity: SEVERITY_NAME[sev],
    time,
    status_id: failed ? STATUS_ID.failure : STATUS_ID.success,
    ...(failed && failureReason ? { status_detail: failureReason } : {}),
    metadata: ocsfMetadata(p, PRODUCTS.entra),
    user: { ...(upn ? { name: upn, email_addr: upn.includes("@") ? upn : undefined } : {}), ...(userId ? { uid: userId } : {}), type_id: 1 },
    ...(ip || country ? { src_endpoint: { ...(ip ? { ip } : {}), ...(country ? { location: { country, ...(str(location?.city) ? { city: str(location?.city) } : {}) } } : {}) } } : {}),
    ...(str(raw.appDisplayName) || str(raw.appId) ? { service: { ...(str(raw.appDisplayName) ? { name: str(raw.appDisplayName) } : {}), ...(str(raw.appId) ? { uid: str(raw.appId) } : {}) } } : {}),
    is_mfa: requirement.includes("multifactor"),
    auth_protocol_id: protocolId,
    ...(protocol ? { auth_protocol: String(raw.authenticationProtocol) } : {}),
    unmapped: { client_app_used: raw.clientAppUsed ?? null },
  };
}

/** A provider vulnerability as an OCSF Vulnerability Finding (2002). */
export function toVulnerabilityFinding(v: NormalisedVulnerability, p: Provenance & { assetName?: string | null; severity?: Severity; observedAt?: Date }): VulnerabilityFinding {
  const sev = severityId(p.severity ?? (v.cvss === null ? "medium" : v.cvss >= 9 ? "critical" : v.cvss >= 7 ? "high" : v.cvss >= 4 ? "medium" : "low"));
  const pkg = v.packageName && v.packageVersion ? [{ name: v.packageName, version: v.packageVersion, ...(v.fixedVersion ? { fixed_in_version: v.fixedVersion } : {}) }] : undefined;
  return {
    ...classFields("vulnerability_finding", FINDING_ACTIVITY.create, "Create"),
    class_uid: 2002,
    severity_id: sev,
    severity: SEVERITY_NAME[sev],
    time: (p.observedAt ?? p.ingestedAt).getTime(),
    status_id: FINDING_STATUS.new,
    metadata: ocsfMetadata(p),
    finding_info: { uid: `${v.assetExternalId}:${v.cve}`, ...(v.title ? { title: v.title } : {}) },
    vulnerabilities: [{
      cve: { uid: v.cve, ...(v.cvss !== null ? { cvss: [{ version: "3.1", base_score: v.cvss }] } : {}) },
      ...(v.title ? { title: v.title } : {}),
      ...(pkg ? { affected_packages: pkg } : {}),
      is_fix_available: !!v.fixedVersion,
    }],
    resources: [{ uid: v.assetExternalId, ...(p.assetName ? { name: p.assetName } : {}) }],
  };
}

/**
 * The OCSF records blakSOC stores for an ingested alert: the Detection Finding for the alert
 * itself, and, when the alert wraps a single source record blakSOC understands, that record in
 * its activity class (firewall syslog → Network Activity, Entra sign-in → Authentication).
 */
export function ocsfForAlert(alert: NormalisedAlert, p: Provenance, extra: { observables?: Observable[]; riskScore?: number } = {}): { finding: DetectionFinding; sourceEvent: NetworkActivity | Authentication | null } {
  const finding = toDetectionFinding(alert, p, extra);
  let sourceEvent: NetworkActivity | Authentication | null = null;
  if (p.source === "syslog") sourceEvent = syslogToNetworkActivity(alert, p);
  else if ((p.source === "entra" || p.source === "m365") && typeof alert.raw.createdDateTime === "string" && "userPrincipalName" in alert.raw) {
    sourceEvent = entraSignInToAuthentication(alert.raw, p);
  }
  return { finding, sourceEvent };
}
