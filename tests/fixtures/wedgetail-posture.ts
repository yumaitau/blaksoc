/** Fictional Wedgetail MCP results (ism_status, mitre_coverage, essential_eight_summary structuredContent). */
export const TOKEN = `wtp_${"a".repeat(22)}.${"b".repeat(43)}`;
export const ISM = {
  release: { name: "September 2026", oscal: "v2026.09.4", mapVersion: "2026.10.2" },
  generatedAt: "2026-10-13T00:00:00.000Z",
  counts: { met: 1, partial: 1, not_met: 1, not_applicable: 0 },
  controls: [
    { id: "ISM-1509", title: "Privileged access events are logged", topic: "privileged", responsibility: "wedgetail", owner: "CISO", status: "met", reason: "Root rule active", e8: [2, 3], verified: true, detections: { mapped: 4, active: 4 } },
    { id: "ISM-1228", title: "Events analysed", topic: "logging", responsibility: "shared", owner: "SOC", status: "partial", reason: "1 source late", verified: true, review: "Check scope" },
    { id: "ISM-0859", title: "Withdrawn", topic: "logging", responsibility: "customer", owner: "CISO", status: "not_met", reason: "Retention 90 days", verified: false, withdrawn: true },
  ],
};
export const MITRE = {
  version: "19.2",
  tactics: [
    { id: "TA0001", shortname: "initial-access", name: "Initial Access", techniques: [{ id: "T1078", name: "Valid Accounts", rules: ["WT-AWS-001", "WT-AWS-002"], disabledRules: [], hunting: [], platforms: ["IaaS"] }, { id: "T1190", name: "Exploit", rules: [], disabledRules: ["WT-X"], hunting: [], platforms: [] }] },
    { id: "TA0003", shortname: "persistence", name: "Persistence", techniques: [{ id: "T1078", name: "Valid Accounts", rules: ["WT-AWS-001", "WT-AWS-002"], disabledRules: [], hunting: ["H-1"], platforms: [] }] },
  ],
  other: [{ id: "AML.T0051.001", rules: ["WT-AI-002"], hunting: [] }],
  gaps: [{ id: "T1190", name: "Exploit", tactics: ["initial-access"], platforms: [] }],
  totals: { techniques: 697, covered: 2, relevant: 120, relevantCovered: 2 },
};

const level = (level: 1 | 2 | 3, met: number, gap: number) => ({ level, total: met + gap, counts: { met, partly_met: 0, gap, outside_wedgetail: 0, attested: 0 } });
export const E8 = {
  model: "ACSC Essential Eight Maturity Model, November 2023",
  generatedAt: "2026-10-13T00:00:00.000Z",
  strategies: [
    { strategy: "multi_factor_authentication", title: "Multi-factor authentication", maturity: 1, levels: [level(1, 4, 0), level(2, 3, 2), level(3, 1, 5)], requirements: [{ id: "E8-MFA-ML1-01", level: 1, status: "met" }] },
    { strategy: "restrict_admin_privileges", title: "Restrict administrative privileges", maturity: 0, levels: [level(1, 2, 1), level(2, 0, 4), level(3, 0, 6)], requirements: [] },
    { strategy: "future_strategy", title: "Not in blakSOC", maturity: 3, levels: [], requirements: [] },
  ],
};
