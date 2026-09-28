import type { RiskFactor } from "@/db/schema";
import type { IntelContext } from "@/db/schema";

/**
 * blakSOC risk engine. Deterministic and additive: every point in the 0–100 score is
 * attributable to a named factor with evidence. No model output feeds this score.
 */

export type AlertRiskInput = {
  severity: "informational" | "low" | "medium" | "high" | "critical";
  siemSeverity: number | null;
  source: string;
  asset: { id: string; name: string; criticality: number; exposure: string } | null;
  identity: { name: string; privileged: boolean } | null;
  intel: IntelContext | null;
  attackTechniques: string[];
  /** Similar alerts for the same asset/rule in the last 24h, excluding this one. */
  repeatCount: number;
  cves: { cve: string; kev: boolean; epss: number | null }[];
  /** Tenant currently has an open incident touching the same asset. */
  openIncidentOnAsset: boolean;
};

const SEVERITY_POINTS = { informational: 2, low: 8, medium: 16, high: 24, critical: 30 } as const;

/** Techniques that usually mean hands-on-keyboard or impact, not noise. */
export const HIGH_IMPACT_TECHNIQUES: Record<string, string> = {
  T1486: "Data Encrypted for Impact",
  T1490: "Inhibit System Recovery",
  T1003: "OS Credential Dumping",
  T1078: "Valid Accounts",
  T1021: "Remote Services",
  T1059: "Command and Scripting Interpreter",
  T1105: "Ingress Tool Transfer",
  T1190: "Exploit Public-Facing Application",
  T1566: "Phishing",
  T1110: "Brute Force",
  T1562: "Impair Defenses",
  T1567: "Exfiltration Over Web Service",
};

export function scoreAlert(input: AlertRiskInput): { score: number; factors: RiskFactor[] } {
  const factors: RiskFactor[] = [];
  const push = (f: RiskFactor) => f.points !== 0 && factors.push(f);

  push({
    key: "siem_severity",
    label: "SIEM severity",
    points: SEVERITY_POINTS[input.severity],
    evidence: `${input.source} reported ${input.severity}${input.siemSeverity != null ? ` (native level ${input.siemSeverity})` : ""}`,
  });

  if (input.asset) {
    const pts = [0, 0, 2, 5, 9, 14][Math.max(0, Math.min(5, input.asset.criticality))] ?? 0;
    push({ key: "asset_criticality", label: "Asset criticality", points: pts, evidence: `${input.asset.name} criticality ${input.asset.criticality}/5`, ref: { type: "asset", id: input.asset.id } });
    if (input.asset.exposure === "internet") {
      push({ key: "exposure", label: "Internet exposure", points: 6, evidence: `${input.asset.name} is internet-facing`, ref: { type: "asset", id: input.asset.id } });
    }
  }

  if (input.identity?.privileged) {
    push({ key: "identity_privilege", label: "Privileged identity", points: 10, evidence: `${input.identity.name} holds privileged access` });
  }

  const matches = input.intel?.matches ?? [];
  const malicious = matches.filter((m) => m.verdict === "malicious");
  const suspicious = matches.filter((m) => m.verdict === "suspicious");
  if (malicious.length) {
    const best = malicious.reduce((a, b) => ((b.score ?? 0) > (a.score ?? 0) ? b : a));
    const conf = best.confidence ?? best.score ?? 50;
    push({
      key: "intel_malicious",
      label: "Threat intelligence match",
      points: Math.round(12 + (conf / 100) * 10),
      evidence: `${best.observable.value} rated malicious by ${best.source ?? "OpenCTI"} (score ${best.score ?? "n/a"}, confidence ${best.confidence ?? "n/a"})`,
      ref: { type: "opencti", id: best.openctiId },
    });
    const actors = [...new Set(malicious.flatMap((m) => [...m.threatActors, ...m.intrusionSets, ...m.malware]))];
    if (actors.length) {
      push({ key: "intel_attribution", label: "Known threat association", points: 5, evidence: `Linked to ${actors.slice(0, 3).join(", ")}` });
    }
  } else if (suspicious.length) {
    const s = suspicious[0]!;
    push({ key: "intel_suspicious", label: "Suspicious reputation", points: 6, evidence: `${s.observable.value} rated suspicious by ${s.source ?? "OpenCTI"}`, ref: { type: "opencti", id: s.openctiId } });
  }

  const kev = input.cves.filter((c) => c.kev);
  if (kev.length) {
    push({ key: "known_exploited", label: "Known exploited vulnerability", points: 10, evidence: `${kev.map((c) => c.cve).join(", ")} on CISA KEV` });
  }
  const topEpss = Math.max(0, ...input.cves.map((c) => c.epss ?? 0));
  if (topEpss >= 0.1) {
    push({ key: "epss", label: "Exploit likelihood (EPSS)", points: topEpss >= 0.5 ? 6 : 3, evidence: `EPSS ${(topEpss * 100).toFixed(1)}%` });
  }

  const impactful = input.attackTechniques.filter((t) => HIGH_IMPACT_TECHNIQUES[t.split(".")[0]!]);
  if (impactful.length) {
    push({
      key: "attack_technique",
      label: "High-impact ATT&CK technique",
      points: impactful.some((t) => t.startsWith("T1486") || t.startsWith("T1490")) ? 12 : 6,
      evidence: impactful.map((t) => `${t} ${HIGH_IMPACT_TECHNIQUES[t.split(".")[0]!]}`).join("; "),
    });
  }

  if (input.repeatCount > 0) {
    push({ key: "repeated", label: "Repeated activity", points: Math.min(8, 2 + input.repeatCount), evidence: `${input.repeatCount} similar alert(s) in the last 24h` });
  }
  if (input.openIncidentOnAsset) {
    push({ key: "active_incident", label: "Asset in active incident", points: 5, evidence: "Affected asset is part of an open incident" });
  }

  const raw = factors.reduce((s, f) => s + f.points, 0);
  return { score: Math.max(0, Math.min(100, raw)), factors: factors.sort((a, b) => b.points - a.points) };
}

export type VulnRiskInput = {
  cve: string;
  cvss: number | null;
  epss: number | null;
  epssPercentile: number | null;
  kev: boolean;
  kevRansomware: boolean;
  kevDueDate: string | null;
  openctiThreats: { name: string; type: string }[];
  asset: { id: string; name: string; criticality: number; exposure: string };
  /** An alert referencing this CVE has been seen on this tenant. */
  observedExploitation: boolean;
};

/** Answers "what should this customer patch first?" — every point is explained. */
export function scoreVulnerability(v: VulnRiskInput): { score: number; factors: RiskFactor[] } {
  const f: RiskFactor[] = [];
  if (v.cvss != null) f.push({ key: "cvss", label: "CVSS base", points: Math.round(v.cvss * 2), evidence: `CVSS ${v.cvss.toFixed(1)}` });
  if (v.kev) {
    f.push({
      key: "kev", label: "CISA KEV", points: 25,
      evidence: `Listed on CISA Known Exploited Vulnerabilities${v.kevDueDate ? ` (federal due ${v.kevDueDate})` : ""}${v.kevRansomware ? "; used in ransomware campaigns" : ""}`,
    });
  }
  if (v.epss != null && v.epss > 0.01) {
    f.push({ key: "epss", label: "EPSS", points: Math.round(Math.min(1, v.epss) * 20), evidence: `EPSS ${(v.epss * 100).toFixed(1)}%${v.epssPercentile != null ? ` (p${Math.round(v.epssPercentile * 100)})` : ""}` });
  }
  if (v.openctiThreats.length) {
    f.push({ key: "opencti", label: "Threat intelligence", points: Math.min(12, 6 + v.openctiThreats.length * 2), evidence: `Used by ${v.openctiThreats.slice(0, 3).map((t) => t.name).join(", ")}` });
  }
  f.push({ key: "asset_criticality", label: "Asset criticality", points: [0, 0, 2, 5, 9, 12][v.asset.criticality] ?? 0, evidence: `${v.asset.name} criticality ${v.asset.criticality}/5`, ref: { type: "asset", id: v.asset.id } });
  if (v.asset.exposure === "internet") f.push({ key: "exposure", label: "Internet exposure", points: 10, evidence: `${v.asset.name} is internet-facing`, ref: { type: "asset", id: v.asset.id } });
  if (v.observedExploitation) f.push({ key: "observed", label: "Observed exploitation", points: 15, evidence: "Exploitation activity for this CVE detected in this environment" });
  const factors = f.filter((x) => x.points > 0).sort((a, b) => b.points - a.points);
  return { score: Math.min(100, factors.reduce((s, x) => s + x.points, 0)), factors };
}
