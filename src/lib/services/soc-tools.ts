import type { AccessContext } from "@/lib/auth/access";
import { env } from "@/lib/env";
import { egressFetch } from "@/lib/net/egress";
import { listIntegrations } from "@/lib/services/integrations";

export type ToolState = "ok" | "degraded" | "down" | "unknown";

export type SocTool = {
  key: "wazuh" | "threatsieve" | "kelpie";
  name: string;
  role: string;
  /** Where the analyst opens the tool; null when no address is configured. */
  url: string | null;
  state: ToolState;
  summary: string;
  checkedAt: Date | null;
};

type Status = Pick<SocTool, "state" | "summary" | "checkedAt">;

type IntegrationStatusRow = {
  enabled: boolean;
  status: string;
  lastError: string | null;
  lastSuccessAt: Date | null;
  lastErrorAt: Date | null;
};

const latest = (dates: (Date | null)[]) => dates.reduce<Date | null>((m, d) => (d && (!m || d > m) ? d : m), null);

/** One status for a tool from its integrations' last health checks (the worker probes every 5 minutes). */
export function integrationStatus(rows: IntegrationStatusRow[]): Status {
  const live = rows.filter((r) => r.enabled);
  if (!live.length) return { state: "unknown", summary: rows.length ? "Integration disabled" : "No integration connected", checkedAt: null };
  const checkedAt = latest(live.flatMap((r) => [r.lastSuccessAt, r.lastErrorAt]));
  const healthy = live.filter((r) => r.status === "healthy").length;
  const failing = live.filter((r) => r.status === "error").length;
  const state: ToolState = healthy === live.length ? "ok" : healthy === 0 && failing === live.length ? "down" : healthy || failing ? "degraded" : "unknown";
  if (live.length > 1) return { state, summary: `${healthy} of ${live.length} connections healthy`, checkedAt };
  const [r] = live;
  if (state === "ok") return { state, summary: "Connected", checkedAt };
  if (state === "unknown") return { state, summary: "Not checked yet", checkedAt };
  return { state, summary: r!.lastError ? truncate(r!.lastError) : "Health check failed", checkedAt };
}

function truncate(s: string, n = 120) {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

export type HealthFetch = (url: URL, init: RequestInit) => Promise<Pick<Response, "ok" | "status" | "json">>;

const PROBE_TTL_MS = 60_000;
const probeCache = new Map<string, { at: number; value: Status }>();

/** ThreatSieve has no blakSOC integration: ask its public API health endpoint, at most once a minute per process. */
export async function probeThreatSieve(apiUrl: string, doFetch: HealthFetch = (url, init) => egressFetch(url, init, "public"), now = Date.now()): Promise<Status> {
  const cached = probeCache.get(apiUrl);
  if (cached && now - cached.at < PROBE_TTL_MS) return cached.value;
  const started = Date.now();
  let value: Status;
  try {
    const res = await doFetch(new URL("/health", apiUrl), { headers: { accept: "application/json" }, signal: AbortSignal.timeout(3000) });
    const body = (await res.json().catch(() => null)) as { status?: unknown } | null;
    value = res.ok && body?.status === "ok"
      ? { state: "ok", summary: `API healthy (${Date.now() - started} ms)`, checkedAt: new Date(now) }
      : { state: "down", summary: `API health check returned HTTP ${res.status}`, checkedAt: new Date(now) };
  } catch (err) {
    const timedOut = err instanceof Error && err.name === "TimeoutError";
    value = { state: "down", summary: timedOut ? "API did not answer within 3 seconds" : "API unreachable", checkedAt: new Date(now) };
  }
  probeCache.set(apiUrl, { at: now, value });
  return value;
}

export function clearThreatSieveProbeCache() {
  probeCache.clear();
}

/** The SOC's companion tools, each with a link and its current status. */
export async function socTools(ctx: AccessContext): Promise<SocTool[]> {
  const e = env();
  const rows = await listIntegrations(ctx);
  const of = (provider: string) => rows.filter((r) => r.provider === provider);
  const kelpieRows = of("kelpie");
  const kelpieBase = kelpieRows.map((r) => (r.config as { baseUrl?: unknown }).baseUrl).find((u): u is string => typeof u === "string");

  const threatsieve: Status = e.THREATSIEVE_API_URL
    ? await probeThreatSieve(e.THREATSIEVE_API_URL)
    : { state: "unknown", summary: "THREATSIEVE_API_URL not configured", checkedAt: null };

  return [
    { key: "wazuh", name: "Wazuh", role: "SIEM and endpoint telemetry", url: e.WAZUH_DASHBOARD_URL ?? null, ...integrationStatus(of("wazuh")) },
    { key: "threatsieve", name: "ThreatSieve", role: "Threat intelligence triage", url: e.THREATSIEVE_URL ?? null, ...threatsieve },
    { key: "kelpie", name: "Kelpie", role: "Incident case management", url: e.KELPIE_URL ?? kelpieBase ?? null, ...integrationStatus(kelpieRows) },
  ];
}
