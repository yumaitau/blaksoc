import { describe, expect, it } from "vitest";
import { extractObservables } from "@/lib/intel/observables";
import { demoRecords } from "@/lib/providers/m365/fixtures";
import { emptyCheckpoint, normaliseSignIn } from "@/lib/providers/m365/normalise";
import type { NormalisedAlert } from "@/lib/providers/types";
import { normaliseSyslog } from "@/lib/syslog/parse";
import { entraSignInToAuthentication, ocsfAttacks, ocsfForAlert, syslogToNetworkActivity, toDetectionFinding, toVulnerabilityFinding, type Provenance } from "@/lib/ocsf/map";
import { NORMALIZATION_VERSION, OCSF_VERSION } from "@/lib/ocsf/schema";
import { validateOcsf } from "@/lib/ocsf/validate";
import { SYSLOG_LINES } from "../fixtures/syslog";

const TENANT = "11111111-1111-4111-8111-111111111111";
const prov = (source: string, sourceEventId: string): Provenance => ({ source, sourceEventId, tenantId: TENANT, ingestedAt: new Date("2026-06-01T01:05:00Z"), processedAt: new Date("2026-06-01T01:05:01Z") });

const wazuhAlert: NormalisedAlert = {
  externalId: "1717203723.1234",
  ruleId: "92057",
  title: "Encoded PowerShell command",
  description: "powershell -enc on FS01",
  category: "execution",
  siemSeverity: 12,
  severity: "high",
  occurredAt: new Date("2026-06-01T01:02:03Z"),
  assetExternalId: "007",
  hostname: "FS01",
  userName: "CORP\\svc-backup",
  attackTechniques: ["T1059.001", "T1027", "not-a-technique"],
  routingKeys: ["wattle"],
  raw: { data: { srcip: "203.0.113.10" }, full_log: "powershell -enc SQBFAFgA from 203.0.113.10 fetching http://evil.example/p.ps1" },
};

describe("OCSF detection findings", () => {
  it("maps any provider alert to a valid Detection Finding with provenance", () => {
    const obs = extractObservables(wazuhAlert.raw);
    const f = toDetectionFinding(wazuhAlert, prov("wazuh", wazuhAlert.externalId), { observables: obs, riskScore: 74 });
    expect(validateOcsf(f)).toEqual({ ok: true });
    expect(f).toMatchObject({
      class_uid: 2004, category_uid: 2, activity_id: 1, type_uid: 200401, severity_id: 4, status_id: 1, is_alert: true, risk_score: 74,
      time: Date.parse("2026-06-01T01:02:03Z"),
      finding_info: { uid: "1717203723.1234", title: "Encoded PowerShell command", types: ["execution"], analytic: { type_id: 1, uid: "92057" } },
      metadata: {
        version: OCSF_VERSION, product: { name: "Wazuh", vendor_name: "Wazuh" }, original_event_uid: "1717203723.1234", tenant_uid: TENANT, log_name: "wazuh",
        logged_time: Date.parse("2026-06-01T01:05:00Z"), transformation_info_list: [{ uid: NORMALIZATION_VERSION }],
      },
      evidences: [{ device: { hostname: "FS01", uid: "007" }, user: { name: "CORP\\svc-backup" } }],
      unmapped: { siem_severity: 12 },
    });
    expect(f.observables).toEqual(expect.arrayContaining([
      expect.objectContaining({ type_id: 2, value: "203.0.113.10" }),
      expect.objectContaining({ type_id: 6, value: "http://evil.example/p.ps1" }),
    ]));
  });

  it("splits ATT&CK sub-techniques and drops anything that is not a technique id", () => {
    expect(ocsfAttacks(["T1059.001", "t1027", "T1027", "TA0002", "bogus"])).toEqual([
      { technique: { uid: "T1059" }, sub_technique: { uid: "T1059.001" } },
      { technique: { uid: "T1027" } },
    ]);
  });
});

describe("OCSF source events", () => {
  it("maps every supported firewall's syslog line to valid Network Activity", () => {
    for (const [vendor, line] of Object.entries(SYSLOG_LINES)) {
      const alert = normaliseSyslog({ id: `row-${vendor}`, line, byteLen: line.length, ingestedAt: new Date("2026-06-01T01:05:00Z") }, TENANT)!;
      const event = syslogToNetworkActivity(alert, prov("syslog", alert.externalId));
      expect(event, vendor).not.toBeNull();
      expect(validateOcsf(event!), vendor).toEqual({ ok: true });
      expect(event!).toMatchObject({ class_uid: 4001, category_uid: 4, activity_id: 6, type_uid: 400106, src_endpoint: { ip: expect.stringMatching(/^203\.0\.113\./) }, dst_endpoint: { ip: expect.stringMatching(/^198\.51\.100\./) } });
    }
  });

  it("records a dropped connection as denied and blocked", () => {
    const line = SYSLOG_LINES.fortinet;
    const alert = normaliseSyslog({ id: "row-1", line, byteLen: line.length, ingestedAt: new Date() }, TENANT)!;
    const event = syslogToNetworkActivity(alert, prov("syslog", "row-1"))!;
    expect(event).toMatchObject({ action_id: 2, disposition_id: 2, src_endpoint: { ip: "203.0.113.10", port: 54321 }, dst_endpoint: { ip: "198.51.100.20", port: 443 }, metadata: { product: { vendor_name: "Fortinet" } } });
  });

  it("maps Entra sign-ins to valid Authentication events", () => {
    const { signIns } = demoRecords(Date.parse("2026-06-01T06:00:00Z"));
    const legacy = entraSignInToAuthentication(signIns[0]!, prov("entra", "signin:si-legacy"))!;
    expect(validateOcsf(legacy)).toEqual({ ok: true });
    expect(legacy).toMatchObject({ class_uid: 3002, category_uid: 3, activity_id: 1, type_uid: 300201, status_id: 1, is_mfa: false, user: { name: "finance@wattle.example", uid: "user-finance" }, src_endpoint: { ip: "203.0.113.10", location: { country: "US" } }, metadata: { product: { name: "Microsoft Entra ID" } } });
    const denied = entraSignInToAuthentication(signIns.find((s) => s.id === "si-mfa-1")!, prov("entra", "signin:si-mfa-1"))!;
    expect(denied).toMatchObject({ status_id: 2, is_mfa: true, severity_id: 2 });
  });

  it("stores a legacy-auth alert as a finding plus its Authentication record", () => {
    const { signIns } = demoRecords(Date.now());
    const { alert } = normaliseSignIn(signIns[0]!, emptyCheckpoint(new Date(Date.now() - 24 * 3600_000)));
    const { finding, sourceEvent } = ocsfForAlert(alert!, prov("entra", alert!.externalId));
    expect(validateOcsf(finding)).toEqual({ ok: true });
    expect(sourceEvent?.class_uid).toBe(3002);
    expect(finding.finding_info.attacks).toEqual([{ technique: { uid: "T1078" } }]);
  });
});

describe("OCSF vulnerability findings", () => {
  it("maps a provider vulnerability to a valid Vulnerability Finding", () => {
    const v = toVulnerabilityFinding({ assetExternalId: "007", cve: "CVE-2024-3400", title: "PAN-OS command injection", packageName: "pan-os", packageVersion: "10.2.9", fixedVersion: "10.2.9-h1", cvss: 10 }, { ...prov("wazuh", "007:CVE-2024-3400"), assetName: "FW01" });
    expect(validateOcsf(v)).toEqual({ ok: true });
    expect(v).toMatchObject({ class_uid: 2002, type_uid: 200201, severity_id: 5, vulnerabilities: [{ cve: { uid: "CVE-2024-3400", cvss: [{ base_score: 10 }] }, affected_packages: [{ name: "pan-os", version: "10.2.9", fixed_in_version: "10.2.9-h1" }], is_fix_available: true }], resources: [{ uid: "007", name: "FW01" }] });
  });
});

describe("OCSF validation", () => {
  const good = () => toDetectionFinding(wazuhAlert, prov("wazuh", wazuhAlert.externalId));

  it("rejects a wrong type_uid, category or severity", () => {
    expect(validateOcsf({ ...good(), type_uid: 200402 })).toMatchObject({ ok: false, errors: [expect.stringMatching(/type_uid/)] });
    expect(validateOcsf({ ...good(), category_uid: 4 })).toMatchObject({ ok: false });
    expect(validateOcsf({ ...good(), severity_id: 7 })).toMatchObject({ ok: false });
  });

  it("rejects missing required attributes and empty identifier objects", () => {
    const { finding_info: _drop, ...noInfo } = good();
    expect(validateOcsf(noInfo)).toMatchObject({ ok: false, errors: [expect.stringMatching(/finding_info/)] });
    expect(validateOcsf({ ...good(), metadata: { version: OCSF_VERSION, product: {} } })).toMatchObject({ ok: false });
    expect(validateOcsf({ ...good(), evidences: [{ device: { type_id: 0 } }] })).toMatchObject({ ok: false });
    expect(validateOcsf({ class_uid: 9999 })).toEqual({ ok: false, errors: ["unsupported class_uid 9999"] });
  });
});
