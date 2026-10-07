import type { Permission } from "@/lib/auth/permissions";

export type NavItem = { href: string; label: string; icon: string; perm: Permission; platformOnly?: boolean; customerOnly?: boolean };
export type NavGroup = { label: string; items: NavItem[] };

export const NAV: NavGroup[] = [
  {
    label: "Operate",
    items: [
      { href: "/soc", label: "SOC dashboard", icon: "LayoutDashboard", perm: "dashboard:read", platformOnly: true },
      { href: "/soc/mssp", label: "Customers", icon: "Building2", perm: "mssp:read", platformOnly: true },
      { href: "/soc/trends", label: "Trends", icon: "ChartColumn", perm: "mssp:read", platformOnly: true },
      { href: "/soc/training", label: "Training", icon: "GraduationCap", perm: "alert:assign", platformOnly: true },
      { href: "/soc/alerts", label: "Alert queue", icon: "Siren", perm: "alert:triage" },
      { href: "/soc/incidents", label: "Incidents", icon: "FolderKanban", perm: "incident:read" },
      { href: "/soc/approvals", label: "Approvals", icon: "ShieldCheck", perm: "response:approve" },
      { href: "/portal", label: "Security overview", icon: "LayoutDashboard", perm: "portal:read" },
      { href: "/portal/usage", label: "Usage", icon: "FileText", perm: "portal:read" },
      { href: "/portal/trends", label: "Trends", icon: "ChartColumn", perm: "alert:read", customerOnly: true },
    ],
  },
  {
    label: "Investigate",
    items: [
      { href: "/soc/hunt", label: "Event search", icon: "SearchCode", perm: "alert:triage" },
      { href: "/assets", label: "Assets", icon: "Server", perm: "asset:read" },
      { href: "/vulnerabilities", label: "Vulnerabilities", icon: "Bug", perm: "vuln:read" },
      { href: "/intel", label: "Threat intelligence", icon: "Radar", perm: "intel:read", platformOnly: true },
      { href: "/assistant", label: "AI analyst", icon: "Sparkles", perm: "ai:use", platformOnly: true },
    ],
  },
  {
    label: "Detect & respond",
    items: [
      { href: "/detections", label: "Detections", icon: "ScanSearch", perm: "detection:read", platformOnly: true },
      { href: "/detections/attack", label: "ATT&CK coverage", icon: "Grid3x3", perm: "detection:read", platformOnly: true },
      { href: "/soar/playbooks", label: "Playbooks", icon: "Workflow", perm: "playbook:read", platformOnly: true },
    ],
  },
  {
    label: "Govern",
    items: [
      { href: "/reports", label: "Reports", icon: "FileText", perm: "report:read" },
      { href: "/soc/usage", label: "Usage", icon: "FileText", perm: "mssp:read", platformOnly: true },
      { href: "/integrations", label: "Integrations", icon: "Plug", perm: "integration:read", platformOnly: true },
      { href: "/admin", label: "Administration", icon: "Settings", perm: "user:manage" },
      { href: "/admin/audit", label: "Audit trail", icon: "ScrollText", perm: "audit:read" },
    ],
  },
];
