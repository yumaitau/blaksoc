import type { WallboardPanel } from "./layout";

export type WallboardCounts = {
  openAlerts: number;
  criticalAlerts: number;
  awaitingTriage: number;
  unassigned: number;
  activeIncidents: number;
  overdueIncidents: number;
  pendingApprovals: number;
  /** Active-lane alerts that arrived in the last hour. */
  newLastHour: number;
  /** Active-lane alerts last changed to resolved or false positive in the last 24 hours. */
  closedLast24h: number;
  /** Open alerts whose indicators matched malicious or suspicious threat intelligence. */
  intelMatched: number;
  incidentsOpened24h: number;
  incidentsClosed24h: number;
};

export const WALLBOARD_SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
export type WallboardSeverity = (typeof WALLBOARD_SEVERITIES)[number];

export type WallboardCustomer = {
  id: string;
  name: string;
  openAlerts: number;
  criticalAlerts: number;
  awaitingTriage: number;
  activeIncidents: number;
  offlineEndpoints: number;
  endpoints: number;
  healthAlerts: number;
  risk: number;
};

export type WallboardIncident = {
  id: string;
  ref: number;
  severity: string;
  status: string;
  tenantName: string;
  slaDueAt: string | null;
  createdAt: string;
};

export type WallboardSnapshot = {
  generatedAt: string;
  scopeName: string;
  customerCount: number;
  counts: WallboardCounts;
  activity: { hour: string; count: number }[];
  severity: Record<WallboardSeverity, number>;
  /** When the longest-waiting untriaged alert occurred. */
  oldestUntriagedAt: string | null;
  /** ATT&CK techniques seen in the last 24 hours. Catalogue names only, never alert content. */
  techniques: { id: string; name: string | null; count: number }[];
  customers: WallboardCustomer[];
  incidentSummary: WallboardIncident[];
  linkExpiresAt: string | null;
  /** The published panel arrangement, or the draft when a manager is previewing. */
  layout: WallboardPanel[];
  preview: boolean;
};

export const WALLBOARD_EXPIRY_DAYS = [1, 7, 30, 90] as const;
export type WallboardExpiryDays = (typeof WALLBOARD_EXPIRY_DAYS)[number];
