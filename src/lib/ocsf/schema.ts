/**
 * blakSOC's canonical event schema: a typed subset of OCSF (Open Cybersecurity Schema Framework).
 *
 * Class ids, enums and required fields were checked against the OCSF schema server
 * (https://schema.ocsf.io/api, version 1.9.0, no profiles). Only the attributes blakSOC writes
 * are typed here; any other OCSF attribute may be added as the mappers grow.
 *
 * Provenance required by the enterprise program maps onto OCSF metadata:
 *   source               metadata.log_name (+ metadata.product)
 *   source_event_id      metadata.original_event_uid
 *   tenant               metadata.tenant_uid
 *   timestamp            time
 *   ingestion_timestamp  metadata.logged_time
 *   normalization_version metadata.transformation_info_list[0].uid (also its own column)
 *   raw_reference        the row's `raw` column; raw_data is not copied into the event
 */

export const OCSF_VERSION = "1.9.0";

/** Bump when a mapper changes what it writes, so stored events can be told apart and re-normalised. */
export const NORMALIZATION_VERSION = "blaksoc-ocsf/1";

export const OCSF_CLASSES = {
  process_activity: { class_uid: 1007, category_uid: 1, class_name: "Process Activity", category_name: "System Activity" },
  vulnerability_finding: { class_uid: 2002, category_uid: 2, class_name: "Vulnerability Finding", category_name: "Findings" },
  detection_finding: { class_uid: 2004, category_uid: 2, class_name: "Detection Finding", category_name: "Findings" },
  authentication: { class_uid: 3002, category_uid: 3, class_name: "Authentication", category_name: "Identity & Access Management" },
  network_activity: { class_uid: 4001, category_uid: 4, class_name: "Network Activity", category_name: "Network Activity" },
} as const;

export type OcsfClassKey = keyof typeof OCSF_CLASSES;

export const SEVERITY_ID = { unknown: 0, informational: 1, low: 2, medium: 3, high: 4, critical: 5, fatal: 6, other: 99 } as const;
export const SEVERITY_NAME: Record<number, string> = { 0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal", 99: "Other" };

/** observable.type_id values blakSOC emits. OCSF has no Domain type: domain names are Hostname. */
export const OBSERVABLE_TYPE_ID = {
  hostname: 1,
  ip_address: 2,
  user_name: 4,
  email_address: 5,
  url_string: 6,
  hash: 8,
  cve: 18,
} as const;

export const FINDING_ACTIVITY = { create: 1, update: 2, close: 3 } as const;
export const FINDING_STATUS = { new: 1, in_progress: 2, suppressed: 3, resolved: 4, archived: 5 } as const;
export const AUTH_ACTIVITY = { logon: 1, logoff: 2 } as const;
export const NETWORK_ACTIVITY = { open: 1, close: 2, reset: 3, fail: 4, refuse: 5, traffic: 6 } as const;
export const ACTION_ID = { unknown: 0, allowed: 1, denied: 2, observed: 3, modified: 4 } as const;
export const DISPOSITION_ID = { unknown: 0, allowed: 1, blocked: 2 } as const;
export const STATUS_ID = { unknown: 0, success: 1, failure: 2 } as const;
export const ANALYTIC_TYPE_ID = { unknown: 0, rule: 1, behavioral: 2, statistical: 3 } as const;
export const AUTH_PROTOCOL_ID = { unknown: 0, ntlm: 1, kerberos: 2, openid: 4, saml: 5, oauth2: 6, other: 99 } as const;

export type OcsfProduct = { name?: string; vendor_name?: string; uid?: string; version?: string };

export type OcsfTransformationInfo = { name?: string; uid?: string; time?: number; url_string?: string };

export type OcsfMetadata = {
  version: string;
  product: OcsfProduct;
  uid?: string;
  original_event_uid?: string;
  tenant_uid?: string;
  log_name?: string;
  logged_time?: number;
  processed_time?: number;
  transformation_info_list?: OcsfTransformationInfo[];
  labels?: string[];
};

export type OcsfObservable = { type_id: number; type?: string; name?: string; value?: string };

export type OcsfUser = { name?: string; uid?: string; email_addr?: string; type_id?: number; domain?: string };

export type OcsfLocation = { country?: string; city?: string; region?: string };

export type OcsfEndpoint = { ip?: string; port?: number; hostname?: string; name?: string; uid?: string; domain?: string; location?: OcsfLocation };

export type OcsfDevice = { type_id: number; hostname?: string; name?: string; uid?: string; ip?: string };

export type OcsfAttack = { technique?: { uid: string; name?: string }; sub_technique?: { uid: string; name?: string }; tactic?: { uid?: string; name?: string } };

export type OcsfAnalytic = { type_id: number; uid?: string; name?: string };

export type OcsfFindingInfo = {
  uid: string;
  title?: string;
  desc?: string;
  types?: string[];
  analytic?: OcsfAnalytic;
  attacks?: OcsfAttack[];
  created_time?: number;
};

export type OcsfEvidence = { device?: OcsfDevice; user?: OcsfUser; src_endpoint?: OcsfEndpoint; dst_endpoint?: OcsfEndpoint };

export type OcsfConnectionInfo = { direction_id: number; protocol_name?: string };

export type OcsfVulnerability = {
  cve?: { uid: string; title?: string; cvss?: { version: string; base_score: number }[] };
  title?: string;
  affected_packages?: { name: string; version: string; fixed_in_version?: string }[];
  is_fix_available?: boolean;
};

/** Attributes every OCSF event carries. */
export type OcsfBase = {
  class_uid: number;
  class_name?: string;
  category_uid: number;
  category_name?: string;
  activity_id: number;
  activity_name?: string;
  type_uid: number;
  severity_id: number;
  severity?: string;
  time: number;
  message?: string;
  status_id?: number;
  metadata: OcsfMetadata;
  observables?: OcsfObservable[];
  unmapped?: Record<string, unknown>;
};

export type DetectionFinding = OcsfBase & {
  class_uid: 2004;
  finding_info: OcsfFindingInfo;
  is_alert?: boolean;
  confidence_id?: number;
  risk_score?: number;
  evidences?: OcsfEvidence[];
};

export type VulnerabilityFinding = OcsfBase & {
  class_uid: 2002;
  finding_info: OcsfFindingInfo;
  vulnerabilities: OcsfVulnerability[];
  resources?: { uid?: string; name?: string; hostname?: string }[];
};

export type Authentication = OcsfBase & {
  class_uid: 3002;
  user: OcsfUser;
  src_endpoint?: OcsfEndpoint;
  service?: { name?: string; uid?: string };
  is_mfa?: boolean;
  auth_protocol_id?: number;
  auth_protocol?: string;
  status_detail?: string;
};

export type NetworkActivity = OcsfBase & {
  class_uid: 4001;
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
  connection_info?: OcsfConnectionInfo;
  action_id?: number;
  disposition_id?: number;
  device?: OcsfDevice;
};

export type OcsfEvent = DetectionFinding | VulnerabilityFinding | Authentication | NetworkActivity;
