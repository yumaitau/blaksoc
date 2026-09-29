/**
 * Scanner budget. The worker job holds one of these.
 * One active scan per tenant, and at most {@link SCAN_LIMITS.hostsPerMinute} hosts a minute.
 * Egress for that job is the worker NetworkPolicy, documented in docs/SECURITY.md.
 */
export const SCAN_LIMITS = { perTenantConcurrency: 1, hostsPerMinute: 6 };

export type ScanBudget = { inFlight: Set<string>; used: { tenantId: string; at: number; hosts: number }[] };

export function emptyScanBudget(): ScanBudget {
  return { inFlight: new Set(), used: [] };
}

export function admitScan(budget: ScanBudget, tenantId: string, hosts: number, now: number): boolean {
  if (hosts < 1) return false;
  if (budget.inFlight.has(tenantId)) return false;
  const recent = budget.used.filter((row) => row.tenantId === tenantId && now - row.at < 60_000);
  const count = recent.reduce((sum, row) => sum + row.hosts, 0);
  if (count + hosts > SCAN_LIMITS.hostsPerMinute) return false;
  budget.inFlight.add(tenantId);
  budget.used.push({ tenantId, at: now, hosts });
  return true;
}

export function releaseScan(budget: ScanBudget, tenantId: string) {
  budget.inFlight.delete(tenantId);
}

export type ScanObservation = {
  host: string;
  ip: string;
  port: number;
  service: "rdp" | "smb" | "vpn" | "https" | "other";
  cve?: string;
  kev?: boolean;
  /** ISO time the certificate stops being valid. */
  tlsNotAfter?: string;
  request: string;
  response: string;
};

export type ClassifiedFinding = {
  p1: boolean;
  certWindow: 30 | 14 | 3 | null;
  code: string;
  title: string;
  evidence: { request: string; response: string };
  cve: string;
  kev: boolean;
};

/** Tightest warning the certificate has entered. 40 days is quiet. 20, 10, and 2 days are 30, 14, and 3. */
export function certWindow(notAfter: Date, now: Date): 30 | 14 | 3 | null {
  const days = Math.ceil((notAfter.getTime() - now.getTime()) / 86_400_000);
  if (days <= 3) return 3;
  if (days <= 14) return 14;
  if (days <= 30) return 30;
  return null;
}

export function classifyObservation(obs: ScanObservation, now: Date): ClassifiedFinding {
  const p1 = obs.service === "rdp" || obs.service === "smb" || (obs.service === "vpn" && obs.kev === true);
  const window = obs.tlsNotAfter ? certWindow(new Date(obs.tlsNotAfter), now) : null;
  const code = p1 ? `ASM-${obs.service.toUpperCase()}` : window ? `CERT-${window}` : obs.cve ? obs.cve : `ASM-${obs.port}`;
  const title = p1
    ? `P1: ${obs.service.toUpperCase()} is exposed on ${obs.host}:${obs.port}`
    : window
      ? `Certificate on ${obs.host} expires inside ${window} days`
      : `Exposed service on ${obs.host}:${obs.port}`;
  return {
    p1,
    certWindow: window,
    code,
    title,
    evidence: { request: obs.request, response: obs.response },
    cve: obs.cve ?? code,
    kev: obs.kev === true,
  };
}
