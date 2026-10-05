export type AbnSource = "abr" | "example" | "unavailable";

export type AbnLookup = {
  abn: string;
  found: boolean;
  name: string | null;
  /** abr: the Australian Business Register answered. example: no ABR_GUID, the example list was used. unavailable: the ABR did not answer. */
  source: AbnSource;
  /** ABR status when found, for example Active or Cancelled. */
  status?: string;
};

const WEIGHTS = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];

/** ATO checksum: subtract 1 from the first digit, weight each digit, and the sum divides by 89. */
export function validAbn(abn: string): boolean {
  if (!/^\d{11}$/.test(abn) || abn[0] === "0") return false;
  const digits = abn.split("").map(Number);
  digits[0]! -= 1;
  return digits.reduce((sum, d, i) => sum + d * WEIGHTS[i]!, 0) % 89 === 0;
}

export function normaliseAbn(raw: string): string {
  return raw.replace(/\D/g, "");
}

/**
 * Without ABR_GUID, checks a short example list.
 * 51824753556 is the ATO's published example, not a customer.
 */
export function lookupExampleAbn(raw: string): AbnLookup {
  const abn = normaliseAbn(raw);
  if (abn === "51824753556") return { abn, found: true, name: "Example Business", source: "example" };
  return { abn, found: false, name: null, source: "example" };
}

type AbrDetails = { Abn?: string; AbnStatus?: string; EntityName?: string; BusinessName?: string[]; Message?: string };

/** The JSON service wraps its answer in a callback. */
export function parseAbrJsonp(body: string): AbrDetails {
  const start = body.indexOf("(");
  const end = body.lastIndexOf(")");
  if (start < 0 || end <= start) throw new Error("ABR reply was not JSONP");
  return JSON.parse(body.slice(start + 1, end)) as AbrDetails;
}

export type AbnFetch = (url: string, init: { signal: AbortSignal }) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

/**
 * Looks the ABN up on the Australian Business Register when a GUID is configured.
 * An ABR outage never blocks setup: it is recorded as unavailable.
 */
export async function lookupAbn(raw: string, opts: { guid?: string; fetch?: AbnFetch } = {}): Promise<AbnLookup> {
  const abn = normaliseAbn(raw);
  if (!opts.guid) return lookupExampleAbn(abn);
  const url = `https://abr.business.gov.au/json/AbnDetails.aspx?abn=${abn}&callback=c&guid=${encodeURIComponent(opts.guid)}`;
  try {
    const res = await (opts.fetch ?? fetch)(url, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`ABR HTTP ${res.status}`);
    const details = parseAbrJsonp(await res.text());
    // A GUID problem is ours, not the customer's. Do not report it as "not found".
    if (/GUID/i.test(details.Message ?? "")) return { abn, found: false, name: null, source: "unavailable" };
    if (details.Abn !== abn) return { abn, found: false, name: null, source: "abr" };
    const name = details.EntityName?.trim() || details.BusinessName?.find((n) => n.trim())?.trim() || null;
    return { abn, found: true, name, source: "abr", status: details.AbnStatus || undefined };
  } catch {
    return { abn, found: false, name: null, source: "unavailable" };
  }
}
