import { REQUIREMENTS, type StrategyId } from "./requirements";
import type { EvidenceItem, EvidenceStatus } from "./score";

export type TelemetryVuln = {
  cve: string;
  cvss: number | null;
  kev: boolean;
  firstSeen: Date;
  kind: string;
  exposure: string;
};

export type TelemetryIdentity = {
  privileged: boolean;
  mfa: boolean | null;
  internetAccess: boolean | null;
};

export type OfficeMacroSnapshot = {
  disabledWithoutNeed?: boolean;
  internetBlocked?: boolean;
  antivirusScan?: boolean;
  usersCannotChange?: boolean;
  win32Blocked?: boolean;
};

export type TelemetrySnapshot = {
  assets: { kind: string; exposure: string }[];
  vulns: TelemetryVuln[];
  identities: TelemetryIdentity[];
  connectors: string[];
  officeMacros: OfficeMacroSnapshot | null;
};

export type EvidenceBundle = {
  items: EvidenceItem[];
  telemetry: Record<StrategyId, string>;
};

const HOUR = 3_600_000;
const DAY = 86_400_000;
const PROXY = "CISA KEV stands for a working exploit. CVSS 9 or higher stands for a vendor-critical rating.";
const BACKUP = "Backup telemetry is not connected. The answer is the rating. This is not a measured backup status.";
const MACRO_ABSENT = "Macro settings from Intune or Group Policy are not connected. The answer stands.";
const APP_ABSENT = "Application control telemetry is not connected. The answer stands.";
const HARDEN_ABSENT = "Browser and Office hardening telemetry is not connected. The answer stands.";
const PATCH_ABSENT = "This control is not read from vulnerability telemetry. The answer stands.";

const MACRO_KEYS: Record<keyof OfficeMacroSnapshot, string> = {
  disabledWithoutNeed: "om-disabled",
  internetBlocked: "om-internet",
  antivirusScan: "om-antivirus",
  usersCannotChange: "om-users",
  win32Blocked: "om-win32",
};

type Match = (row: { kind: string; exposure: string }) => boolean;

const appInternet: Match = (row) => (row.kind === "application" || row.kind === "saas" || row.kind === "cloud_resource") && row.exposure === "internet";
const osInternet: Match = (row) => (row.kind === "server" || row.kind === "network_device") && row.exposure === "internet";
const osWorkstation: Match = (row) => row.kind === "endpoint" || ((row.kind === "server" || row.kind === "network_device") && row.exposure !== "internet");

function critical(vuln: TelemetryVuln) {
  return vuln.kev || (vuln.cvss != null && vuln.cvss >= 9);
}

function present(snapshot: TelemetrySnapshot, match: Match) {
  return snapshot.assets.some(match) || snapshot.vulns.some(match);
}

/**
 * Turns stored telemetry into per-requirement evidence. Backup rows are ignored:
 * backup measurement is not shipped. A measured line does not pass a "no" answer.
 */
export function evidenceFromTelemetry(snapshot: TelemetrySnapshot, now: Date): EvidenceBundle {
  const lines = new Map<string, { status: EvidenceStatus; detail: string }>();
  const defaults: Record<StrategyId, string> = {
    patch_applications: PATCH_ABSENT,
    patch_os: PATCH_ABSENT,
    mfa: "No Microsoft 365 or Google MFA coverage is in telemetry. The answer stands.",
    restrict_admin: "No identity telemetry. The admin role count is not measurable. The answer stands.",
    application_control: APP_ABSENT,
    office_macros: MACRO_ABSENT,
    user_app_hardening: HARDEN_ABSENT,
    regular_backups: BACKUP,
  };
  for (const row of REQUIREMENTS) lines.set(row.id, { status: "absent", detail: defaults[row.strategy] });

  const bind = (id: string, match: Match, pred: (vuln: TelemetryVuln) => boolean, windowMs: number, empty: string) => {
    if (!present(snapshot, match)) {
      lines.set(id, { status: "absent", detail: empty });
      return;
    }
    const hits = snapshot.vulns.filter((vuln) => match(vuln) && pred(vuln) && now.getTime() - vuln.firstSeen.getTime() > windowMs);
    if (hits.length) {
      const listed = hits.slice(0, 5).map((vuln) => `${vuln.cve} open ${Math.floor((now.getTime() - vuln.firstSeen.getTime()) / HOUR)} hours on ${vuln.exposure} ${vuln.kind}`).join("; ");
      lines.set(id, { status: "contradicts", detail: `${listed}. ${PROXY}` });
    } else {
      lines.set(id, { status: "measured", detail: `No open finding in this class is past the window. ${PROXY}` });
    }
  };

  const noAssets = "No assets of this class are recorded, so patch age is not measured. The answer stands.";
  bind("pa-online-48h", appInternet, critical, 48 * HOUR, noAssets);
  bind("pa-online-2w", appInternet, (vuln) => !critical(vuln), 14 * DAY, noAssets);
  bind("po-inet-48h", osInternet, critical, 48 * HOUR, noAssets);
  bind("po-inet-2w", osInternet, (vuln) => !critical(vuln), 14 * DAY, noAssets);
  bind("po-ws-1mo", osWorkstation, () => true, 30 * DAY, noAssets);
  bind("po-ws-48h", osWorkstation, critical, 48 * HOUR, noAssets);

  const knownMfa = snapshot.identities.filter((row) => row.mfa !== null);
  const connectors = snapshot.connectors.some((provider) => provider === "entra" || provider === "google" || provider === "google_workspace");
  let mfaSummary = defaults.mfa;
  if (knownMfa.length) {
    const missing = knownMfa.filter((row) => row.mfa === false).length;
    mfaSummary = `${knownMfa.length - missing} of ${knownMfa.length} identities with an MFA flag have MFA.`;
    for (const row of REQUIREMENTS.filter((item) => item.strategy === "mfa")) {
      lines.set(row.id, { status: "measured", detail: mfaSummary });
    }
    if (missing > 0) {
      lines.set("mfa-own-sensitive", { status: "contradicts", detail: `${mfaSummary} Coverage is not complete.` });
    }
  } else if (connectors) {
    mfaSummary = "An identity connector is connected. Per-user MFA registration is not in the telemetry, so coverage is not measurable. The answer stands.";
    for (const row of REQUIREMENTS.filter((item) => item.strategy === "mfa")) lines.set(row.id, { status: "absent", detail: mfaSummary });
  }

  const identities = snapshot.identities;
  let adminSummary = defaults.restrict_admin;
  if (identities.length) {
    const privileged = identities.filter((row) => row.privileged).length;
    adminSummary = `${privileged} privileged ${privileged === 1 ? "identity" : "identities"} of ${identities.length}.`;
    for (const row of REQUIREMENTS.filter((item) => item.strategy === "restrict_admin")) {
      lines.set(row.id, { status: "measured", detail: `${adminSummary} This count does not by itself pass a control. The answer stands.` });
    }
    const internet = identities.filter((row) => row.privileged && row.internetAccess === true).length;
    if (internet > 0) {
      lines.set("ra-no-internet", { status: "contradicts", detail: `${adminSummary} ${internet} privileged identities are recorded with internet access.` });
    }
  }

  let macroSummary = MACRO_ABSENT;
  if (snapshot.officeMacros) {
    macroSummary = "Intune or Group Policy macro settings are recorded.";
    for (const row of REQUIREMENTS.filter((item) => item.strategy === "office_macros")) {
      lines.set(row.id, { status: "absent", detail: "This macro control is not in the Intune or Group Policy snapshot. The answer stands." });
    }
    for (const [key, id] of Object.entries(MACRO_KEYS) as [keyof OfficeMacroSnapshot, string][]) {
      const value = snapshot.officeMacros[key];
      if (value === false) lines.set(id, { status: "contradicts", detail: `Intune or Group Policy reports this setting is off. ${macroSummary}` });
      else if (value === true) lines.set(id, { status: "measured", detail: "Intune or Group Policy reports this setting is on." });
    }
  }

  for (const row of REQUIREMENTS.filter((item) => item.strategy === "regular_backups")) {
    lines.set(row.id, { status: "absent", detail: BACKUP });
  }

  const telemetry: Record<StrategyId, string> = {
    patch_applications: patchSummary("patch_applications", lines, "internet-facing applications"),
    patch_os: patchSummary("patch_os", lines, "operating systems"),
    mfa: mfaSummary,
    restrict_admin: adminSummary,
    application_control: APP_ABSENT,
    office_macros: macroSummary,
    user_app_hardening: HARDEN_ABSENT,
    regular_backups: BACKUP,
  };

  return {
    items: REQUIREMENTS.map((row) => ({ requirementId: row.id, ...lines.get(row.id)! })),
    telemetry,
  };
}

function patchSummary(strategy: StrategyId, lines: Map<string, { status: EvidenceStatus; detail: string }>, klass: string) {
  const rows = REQUIREMENTS.filter((row) => row.strategy === strategy).map((row) => lines.get(row.id)!);
  if (rows.some((row) => row.status === "contradicts")) return `Vulnerability telemetry contradicts a ${strategy === "patch_os" ? "patch operating systems" : "patch applications"} answer.`;
  if (rows.some((row) => row.status === "measured")) return `Vulnerability telemetry covers ${klass}.`;
  return `Patch age for ${klass} is not measured.`;
}
