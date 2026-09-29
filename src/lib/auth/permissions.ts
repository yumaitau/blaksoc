/** Every permission blakSOC checks server-side. Roles are sets of these. */
export const PERMISSIONS = [
  "dashboard:read",
  "mssp:read",
  "alert:read",
  "alert:triage",
  "alert:assign",
  "incident:read",
  "incident:write",
  "incident:close",
  "asset:read",
  "asset:write",
  "vuln:read",
  "vuln:write",
  "intel:read",
  "intel:write",
  "intel:share",
  "detection:read",
  "detection:write",
  "detection:deploy",
  "playbook:read",
  "playbook:write",
  "playbook:run",
  "response:request",
  "response:approve",
  "integration:read",
  "integration:manage",
  "report:read",
  "report:generate",
  "ai:use",
  "audit:read",
  "tenant:manage",
  "user:manage",
  "settings:manage",
  "portal:read",
] as const;

export type Permission = (typeof PERMISSIONS)[number];

export type BuiltinRole = {
  key: string;
  name: string;
  scope: "platform" | "tenant";
  description: string;
  permissions: readonly Permission[];
};

const L1: Permission[] = [
  "dashboard:read", "mssp:read", "alert:read", "alert:triage", "incident:read", "incident:write", "asset:read",
  "vuln:read", "intel:read", "detection:read", "playbook:read", "playbook:run", "response:request",
  "integration:read", "report:read", "ai:use",
];
const L2: Permission[] = [
  ...L1, "alert:assign", "incident:close", "asset:write", "vuln:write", "intel:write", "detection:write",
  "report:generate",
];

export const BUILTIN_ROLES: readonly BuiltinRole[] = [
  {
    key: "platform_admin",
    name: "Platform Administrator",
    scope: "platform",
    description: "Operates blakSOC itself: tenants, identity, integrations, policy.",
    permissions: PERMISSIONS.filter((p) => p !== "portal:read"),
  },
  {
    key: "soc_manager",
    name: "SOC Manager",
    scope: "platform",
    description: "Runs the SOC: approvals, detection deployment, playbooks, reporting.",
    permissions: [
      ...L2, "intel:share", "detection:deploy", "playbook:write", "response:approve", "integration:manage", "audit:read",
    ],
  },
  { key: "soc_analyst_l2", name: "SOC Analyst L2/L3", scope: "platform", description: "Investigation and response.", permissions: L2 },
  { key: "soc_analyst_l1", name: "SOC Analyst L1", scope: "platform", description: "Triage and escalation.", permissions: L1 },
  {
    key: "auditor",
    name: "Auditor",
    scope: "platform",
    description: "Read-only oversight including the audit trail.",
    permissions: [
      "dashboard:read", "mssp:read", "alert:read", "incident:read", "asset:read", "vuln:read", "intel:read",
      "detection:read", "playbook:read", "integration:read", "report:read", "audit:read",
    ],
  },
  {
    key: "customer_admin",
    name: "Customer Administrator",
    scope: "tenant",
    description: "Manages their organisation's users and approves containment.",
    permissions: [
      "portal:read", "incident:read", "asset:read", "vuln:read", "report:read", "report:generate", "response:approve",
      "user:manage", "audit:read", "alert:read",
    ],
  },
  {
    key: "customer_security",
    name: "Customer Security User",
    scope: "tenant",
    description: "Customer security staff working alongside the SOC.",
    permissions: ["portal:read", "incident:read", "asset:read", "vuln:read", "report:read", "alert:read"],
  },
  {
    key: "customer_readonly",
    name: "Customer Read Only",
    scope: "tenant",
    description: "Executive / stakeholder view.",
    permissions: ["portal:read", "incident:read", "vuln:read", "report:read"],
  },
  {
    key: "partner_admin",
    name: "Partner Administrator",
    scope: "tenant",
    description: "Runs an IT provider tenancy: its consented customers, onboarding, co-brand, and commercial report.",
    permissions: [
      "dashboard:read", "portal:read", "mssp:read", "tenant:manage", "user:manage", "settings:manage",
      "alert:read", "incident:read", "incident:write", "asset:read", "asset:write", "vuln:read",
      "report:read", "report:generate", "audit:read", "playbook:read", "playbook:write",
    ],
  },
  {
    key: "partner_analyst",
    name: "Partner Analyst",
    scope: "tenant",
    description: "Triages the provider's own customers and escalates to the Yuma IT SOC.",
    permissions: [
      "dashboard:read", "portal:read", "alert:read", "alert:triage", "alert:assign",
      "incident:read", "incident:write", "asset:read", "vuln:read", "intel:read",
      "detection:read", "playbook:read", "report:read",
    ],
  },
];
