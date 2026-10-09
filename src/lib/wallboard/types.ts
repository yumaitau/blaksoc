export type WallboardCounts = {
  openAlerts: number;
  criticalAlerts: number;
  awaitingTriage: number;
  unassigned: number;
  activeIncidents: number;
  overdueIncidents: number;
  pendingApprovals: number;
};

export type WallboardCustomer = {
  id: string;
  name: string;
  openAlerts: number;
  criticalAlerts: number;
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
};

export type WallboardSnapshot = {
  generatedAt: string;
  scopeName: string;
  customerCount: number;
  counts: WallboardCounts;
  activity: { hour: string; count: number }[];
  customers: WallboardCustomer[];
  incidentSummary: WallboardIncident[];
  linkExpiresAt: string | null;
};

export const WALLBOARD_EXPIRY_DAYS = [1, 7, 30, 90] as const;
export type WallboardExpiryDays = (typeof WALLBOARD_EXPIRY_DAYS)[number];
