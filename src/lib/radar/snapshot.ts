/**
 * Cloudflare Radar read API.
 * Token permission: Account > Radar > Read.
 * https://developers.cloudflare.com/radar/get-started/first-request/
 * https://developers.cloudflare.com/api/resources/radar/subresources/attacks/subresources/layer7/methods/summary_v2/
 * https://developers.cloudflare.com/api/resources/radar/subresources/annotations/subresources/outages/methods/get/
 *
 * Figures are Cloudflare's view of Australian internet traffic, not a customer's logs.
 */

export const RADAR_ORIGIN = "https://api.cloudflare.com/client/v4/radar";

const TOKEN = /^[A-Za-z0-9_-]{20,4096}$/;

const ACRONYM = new Set(["http", "https", "udp", "tcp", "icmp", "gre", "ip", "api", "waf", "ddos", "dns", "bgp", "au", "bot"]);

export type RadarShare = { key: string; label: string; pct: number };
export type RadarOutage = {
  id: string;
  start: string;
  end: string | null;
  scope: string;
  cause: string;
  locations: string;
};
export type RadarSection<T> = { rows: T[]; error: string | null };
export type RadarSnapshot = {
  configured: boolean;
  l7: RadarSection<RadarShare>;
  l3: RadarSection<RadarShare>;
  bots: RadarSection<RadarShare>;
  outages: RadarSection<RadarOutage>;
};

export type RadarFetch = (url: string, init: RequestInit) => Promise<Response>;

const empty = <T,>(): RadarSection<T> => ({ rows: [], error: null });

export function unconfiguredRadar(): RadarSnapshot {
  return { configured: false, l7: empty(), l3: empty(), bots: empty(), outages: empty() };
}

export function radarLabel(key: string): string {
  return key
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((part) => {
      const lower = part.toLowerCase();
      if (ACRONYM.has(lower)) return lower.toUpperCase();
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

/** First percentage series. Radar names it `summary_0` unless a comparison series is requested. */
function summaryRecord(result: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!result) return null;
  const primary = record(result.summary_0);
  if (primary) return primary;
  for (const [key, value] of Object.entries(result)) {
    if (key === "meta") continue;
    const series = record(value);
    if (!series) continue;
    const values = Object.values(series);
    if (values.length && values.every((item) => typeof item === "string" || typeof item === "number")) return series;
  }
  return null;
}

/** Percentage buckets from the first summary series. Non-numeric values are skipped. */
export function sharesFrom(body: unknown, limit = 8): RadarShare[] {
  const summary = summaryRecord(record(record(body)?.result));
  if (!summary) return [];
  const rows: RadarShare[] = [];
  for (const [key, value] of Object.entries(summary)) {
    const pct = typeof value === "string" || typeof value === "number" ? Number(value) : Number.NaN;
    if (!Number.isFinite(pct)) continue;
    rows.push({ key, label: radarLabel(key), pct });
  }
  rows.sort((a, b) => b.pct - a.pct || a.key.localeCompare(b.key));
  return rows.slice(0, limit);
}

function locationLabel(row: Record<string, unknown>): string {
  if (Array.isArray(row.locationsDetails)) {
    const names = row.locationsDetails
      .map((item) => {
        const rec = record(item);
        if (!rec) return "";
        if (typeof rec.name === "string" && rec.name) return rec.name;
        return typeof rec.code === "string" ? rec.code : "";
      })
      .filter(Boolean);
    if (names.length) return names.slice(0, 3).join(", ");
  }
  if (Array.isArray(row.locations)) {
    const codes = row.locations.filter((item): item is string => typeof item === "string" && item.length > 0);
    if (codes.length) return codes.slice(0, 3).join(", ");
  }
  return "";
}

/** Latest annotations from GET /radar/annotations/outages. */
export function outagesFrom(body: unknown, limit = 8): RadarOutage[] {
  const list = record(record(body)?.result)?.annotations;
  if (!Array.isArray(list)) return [];
  const out: RadarOutage[] = [];
  for (const item of list) {
    const row = record(item);
    if (!row || typeof row.id !== "string" || !row.id) continue;
    const outage = record(row.outage);
    const type = typeof outage?.outageType === "string" ? radarLabel(outage.outageType) : "";
    const cause = typeof outage?.outageCause === "string" ? radarLabel(outage.outageCause) : "";
    out.push({
      id: row.id,
      start: typeof row.startDate === "string" ? row.startDate : "",
      end: typeof row.endDate === "string" ? row.endDate : null,
      scope: typeof row.scope === "string" ? row.scope : "",
      cause: [type, cause].filter((part, i, all) => part && all.indexOf(part) === i).join(" · "),
      locations: locationLabel(row),
    });
    if (out.length >= limit) break;
  }
  return out;
}

/** Status text only. Radar error strings that mention the credential are not shown. */
export function radarError(body: unknown, status: number): string {
  const errors = record(body)?.errors;
  const first = Array.isArray(errors) ? record(errors[0]) : null;
  const message = first && typeof first.message === "string" ? first.message.slice(0, 180) : "";
  if (message && !/bearer|token|authorization|api[_ ]?key/i.test(message)) return message;
  if (status === 401 || status === 403) return "Cloudflare Radar refused the API token. It needs Account > Radar > Read.";
  return `Cloudflare Radar returned ${status}.`;
}

function query(path: string, params: Record<string, string>): string {
  const url = new URL(path, `${RADAR_ORIGIN}/`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url.toString();
}

/** Paths the dashboard asks for. Australia, short windows, JSON. */
export function radarUrls(): { l7: string; l3: string; bots: string; outages: string } {
  const au = { format: "JSON", location: "AU" };
  return {
    l7: query("attacks/layer7/summary/industry", { ...au, dateRange: "1d", name: "au" }),
    l3: query("attacks/layer3/summary/protocol", { ...au, dateRange: "1d", name: "au" }),
    bots: query("http/summary/bot_class", { ...au, dateRange: "1d", name: "au" }),
    outages: query("annotations/outages", { ...au, dateRange: "7d", limit: "8" }),
  };
}

async function readSection<T>(fetchImpl: RadarFetch, url: string, token: string, parse: (body: unknown) => T[]): Promise<RadarSection<T>> {
  try {
    const res = await fetchImpl(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(8_000),
      cache: "no-store",
    });
    if (res.status >= 300 && res.status < 400) return { rows: [], error: "Cloudflare Radar redirected the request. Nothing was followed." };
    const body: unknown = await res.json().catch(() => null);
    const success = record(body)?.success;
    if (!res.ok || success !== true) return { rows: [], error: radarError(body, res.status) };
    return { rows: parse(body), error: null };
  } catch {
    return { rows: [], error: "Cloudflare Radar did not answer." };
  }
}

/** One round of Radar reads. Does not call Cloudflare when the token is missing or the wrong shape. */
export async function collectRadar(token: string | undefined, fetchImpl: RadarFetch): Promise<RadarSnapshot> {
  const trimmed = token?.trim() ?? "";
  if (!trimmed) return unconfiguredRadar();
  if (!TOKEN.test(trimmed)) {
    const error = "CLOUDFLARE_RADAR_TOKEN is not a Cloudflare API token.";
    const failed = <T,>(): RadarSection<T> => ({ rows: [], error });
    return { configured: true, l7: failed(), l3: failed(), bots: failed(), outages: failed() };
  }
  const urls = radarUrls();
  const [l7, l3, bots, outages] = await Promise.all([
    readSection(fetchImpl, urls.l7, trimmed, sharesFrom),
    readSection(fetchImpl, urls.l3, trimmed, sharesFrom),
    readSection(fetchImpl, urls.bots, trimmed, sharesFrom),
    readSection(fetchImpl, urls.outages, trimmed, outagesFrom),
  ]);
  return { configured: true, l7, l3, bots, outages };
}
