/** Fictional Wedgetail MCP results (ism_status, mitre_coverage structuredContent). */
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

