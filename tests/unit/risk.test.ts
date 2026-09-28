import { describe, expect, it } from "vitest";
import { scoreAlert, scoreVulnerability } from "@/lib/risk/engine";
import type { IntelMatch } from "@/db/schema";

const base = {
  severity: "medium" as const, siemSeverity: 8, source: "wazuh", asset: null, identity: null, intel: null,
  attackTechniques: [], repeatCount: 0, cves: [], openIncidentOnAsset: false,
};

const match = (over: Partial<IntelMatch> = {}): IntelMatch => ({
  observable: { type: "ipv4", value: "185.220.101.47" }, openctiId: "x", entityType: "IPv4-Addr", verdict: "malicious", score: 85, confidence: 80,
  source: "OTX", markings: [], labels: [], firstSeen: null, lastSeen: null, threatActors: [], intrusionSets: ["APT-X"], malware: [], campaigns: [],
  attackPatterns: [], relatedIndicators: [], sightings: 0, ...over,
});

describe("scoreAlert", () => {
  it("every point is attributable to a factor", () => {
    const r = scoreAlert({ ...base, asset: { id: "a", name: "DC01", criticality: 5, exposure: "internet" }, identity: { name: "admin", privileged: true }, intel: { verdict: "malicious", matches: [match()], checkedAt: "" }, attackTechniques: ["T1078"], repeatCount: 3, cves: [{ cve: "CVE-1", kev: true, epss: 0.6 }] });
    expect(r.score).toBe(Math.min(100, r.factors.reduce((s, f) => s + f.points, 0)));
    for (const f of r.factors) expect(f.evidence.length).toBeGreaterThan(0);
  });

  it("clamps to 0-100", () => {
    const r = scoreAlert({ ...base, severity: "critical", asset: { id: "a", name: "x", criticality: 5, exposure: "internet" }, identity: { name: "a", privileged: true }, intel: { verdict: "malicious", matches: [match({ confidence: 100 })], checkedAt: "" }, attackTechniques: ["T1486"], repeatCount: 50, cves: [{ cve: "c", kev: true, epss: 0.9 }], openIncidentOnAsset: true });
    expect(r.score).toBe(100);
  });

  it("intel and asset context raise score above raw SIEM severity", () => {
    const plain = scoreAlert(base).score;
    const enriched = scoreAlert({ ...base, asset: { id: "a", name: "DC01", criticality: 5, exposure: "internal" }, intel: { verdict: "malicious", matches: [match()], checkedAt: "" } }).score;
    expect(enriched).toBeGreaterThan(plain + 20);
  });

  it("suspicious intel scores less than malicious", () => {
    const sus = scoreAlert({ ...base, intel: { verdict: "suspicious", matches: [match({ verdict: "suspicious" })], checkedAt: "" } }).score;
    const mal = scoreAlert({ ...base, intel: { verdict: "malicious", matches: [match()], checkedAt: "" } }).score;
    expect(mal).toBeGreaterThan(sus);
  });

  it("links evidence refs to records", () => {
    const r = scoreAlert({ ...base, asset: { id: "asset-1", name: "x", criticality: 4, exposure: "internal" }, intel: { verdict: "malicious", matches: [match({ openctiId: "indicator--1" })], checkedAt: "" } });
    expect(r.factors.find((f) => f.key === "intel_malicious")?.ref).toEqual({ type: "opencti", id: "indicator--1" });
    expect(r.factors.find((f) => f.key === "asset_criticality")?.ref).toEqual({ type: "asset", id: "asset-1" });
  });
});

describe("scoreVulnerability", () => {
  const asset = { id: "a", name: "VPN", criticality: 5, exposure: "internet" };
  it("KEV on an internet-facing crown jewel outranks high CVSS on a workstation", () => {
    const kev = scoreVulnerability({ cve: "A", cvss: 8, epss: 0.9, epssPercentile: 0.99, kev: true, kevRansomware: false, kevDueDate: null, openctiThreats: [], asset, observedExploitation: false });
    const cvssOnly = scoreVulnerability({ cve: "B", cvss: 9.8, epss: 0.01, epssPercentile: 0.3, kev: false, kevRansomware: false, kevDueDate: null, openctiThreats: [], asset: { id: "b", name: "WS", criticality: 2, exposure: "internal" }, observedExploitation: false });
    expect(kev.score).toBeGreaterThan(cvssOnly.score);
    expect(kev.factors.map((f) => f.key)).toContain("kev");
  });
});
