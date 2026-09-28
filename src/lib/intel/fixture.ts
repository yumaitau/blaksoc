import type { IntelMatch } from "@/db/schema";
import type { Observable } from "./observables";
import type { IntelProvider, IntelSearchResult } from "./types";

/** Deterministic intel for DEMO_MODE and tests, shaped like OpenCTI results. */
const KNOWN: Record<string, Omit<IntelMatch, "observable" | "openctiId" | "entityType" | "sightings">> = {
  "185.220.101.47": {
    verdict: "malicious", score: 85, confidence: 80, source: "AlienVault OTX", markings: ["TLP:CLEAR"], labels: ["tor-exit", "credential-access"],
    firstSeen: "2025-11-02T00:00:00Z", lastSeen: "2026-09-20T00:00:00Z", threatActors: [], intrusionSets: ["APT-C-Bruteforce Cluster"],
    malware: [], campaigns: ["Password spraying against AU M365 tenants"], attackPatterns: [{ id: "T1110.003", name: "Password Spraying" }, { id: "T1078", name: "Valid Accounts" }],
    relatedIndicators: [{ id: "indicator--demo-1", name: "185.220.101.47", pattern: "[ipv4-addr:value = '185.220.101.47']" }],
  },
  "update-check.xyz": {
    verdict: "malicious", score: 90, confidence: 85, source: "URLhaus (abuse.ch)", markings: ["TLP:CLEAR"], labels: ["malware-distribution"],
    firstSeen: "2026-08-14T00:00:00Z", lastSeen: "2026-09-25T00:00:00Z", threatActors: [], intrusionSets: [], malware: ["SocGholish"],
    campaigns: [], attackPatterns: [{ id: "T1059.001", name: "PowerShell" }, { id: "T1105", name: "Ingress Tool Transfer" }],
    relatedIndicators: [{ id: "indicator--demo-2", name: "update-check.xyz", pattern: "[domain-name:value = 'update-check.xyz']" }],
  },
  "b8e0a7c3d7a6f7e8c1d0f3e2a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3": {
    verdict: "malicious", score: 95, confidence: 90, source: "MalwareBazaar (abuse.ch)", markings: ["TLP:CLEAR"], labels: ["lockbit", "ransomware"],
    firstSeen: "2026-07-30T00:00:00Z", lastSeen: "2026-09-26T00:00:00Z", threatActors: [], intrusionSets: ["LockBit affiliates"], malware: ["LockBit 3.0"],
    campaigns: [], attackPatterns: [{ id: "T1486", name: "Data Encrypted for Impact" }],
    relatedIndicators: [{ id: "indicator--demo-3", name: "LockBit loader", pattern: "[file:hashes.'SHA-256' = 'b8e0…a2b3']" }],
  },
  "45.155.205.233": {
    verdict: "suspicious", score: 55, confidence: 60, source: "CIRCL MISP feed", markings: ["TLP:GREEN"], labels: ["scanner", "ssh-bruteforce"],
    firstSeen: "2026-01-11T00:00:00Z", lastSeen: "2026-09-27T00:00:00Z", threatActors: [], intrusionSets: [], malware: ["Mirai"], campaigns: [],
    attackPatterns: [{ id: "T1110.001", name: "Password Guessing" }], relatedIndicators: [],
  },
};

export class FixtureIntelProvider implements IntelProvider {
  readonly kind = "fixture";
  async lookup(observables: Observable[]): Promise<IntelMatch[]> {
    return observables.flatMap((o) => {
      const k = KNOWN[o.value];
      return k ? [{ ...k, observable: { type: o.type, value: o.value }, openctiId: `demo--${o.value.slice(0, 16)}`, entityType: "Stix-Cyber-Observable", sightings: 3 }] : [];
    });
  }
  async cveContext(cves: string[]) {
    return cves.map((cve) => ({ cve, threats: cve === "CVE-2024-3400" ? [{ id: "demo--uta0218", name: "UTA0218", type: "Intrusion-Set" }] : [] }));
  }
  async search(term: string): Promise<IntelSearchResult[]> {
    return Object.entries(KNOWN)
      .filter(([k, v]) => k.includes(term) || v.malware.join(" ").toLowerCase().includes(term.toLowerCase()))
      .map(([k, v]) => ({ id: `demo--${k.slice(0, 16)}`, entityType: "Indicator", name: k, description: v.campaigns[0] ?? null, labels: v.labels, markings: v.markings, score: v.score, createdBy: v.source, modified: v.lastSeen }));
  }
  async createSighting() {
    return { id: `sighting--demo-${Date.now()}` };
  }
  async ensureIdentity(name: string) {
    return `identity--demo-${name}`;
  }
  async createReport() {
    return { id: `report--demo-${Date.now()}` };
  }
  async addLabels() {}
  async health() {
    return { ok: true, latencyMs: 0, detail: { mode: "fixture" } };
  }
}
