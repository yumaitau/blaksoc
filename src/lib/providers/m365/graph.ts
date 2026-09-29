/**
 * Microsoft Graph / Office 365 Management transport.
 * Callers pass a transport so tests replay recorded responses. Live traffic uses client credentials.
 */

export type GraphResult = { status: number; headers: Record<string, string>; body: unknown };

export type GraphTransport = {
  request(method: string, path: string, opts?: { query?: Record<string, string>; body?: unknown }): Promise<GraphResult>;
};

export class GraphError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

function retryAfterMs(headers: Record<string, string>): number {
  const raw = headers["retry-after"];
  const seconds = Number(raw);
  if (Number.isFinite(seconds)) return Math.max(0, seconds) * 1000;
  return 1000;
}

/** GET/POST/PATCH/DELETE with 429 + Retry-After. 403 is returned, not thrown. */
export async function graphRequest(
  transport: GraphTransport,
  method: string,
  path: string,
  opts?: { query?: Record<string, string>; body?: unknown; retries?: number; sleep?: (ms: number) => Promise<void> },
): Promise<GraphResult> {
  const retries = opts?.retries ?? 4;
  const sleep = opts?.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  for (let attempt = 0; ; attempt++) {
    const res = await transport.request(method, path, { query: opts?.query, body: opts?.body });
    const headers = Object.fromEntries(Object.entries(res.headers).map(([k, v]) => [k.toLowerCase(), v]));
    if (res.status !== 429) return { ...res, headers };
    if (attempt >= retries) throw new GraphError(`Graph throttled ${method} ${path}`, 429);
    await sleep(retryAfterMs(headers));
  }
}

export function graphValues(body: unknown): Record<string, unknown>[] {
  if (!body || typeof body !== "object") return [];
  const value = (body as { value?: unknown }).value;
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is Record<string, unknown> => !!v && typeof v === "object");
}

/** Follow @odata.nextLink up to `pages` times. A 403 yields denied:true and whatever was collected. */
export async function graphList(
  transport: GraphTransport,
  path: string,
  query?: Record<string, string>,
  opts?: { sleep?: (ms: number) => Promise<void>; pages?: number },
): Promise<{ records: Record<string, unknown>[]; denied: boolean }> {
  const records: Record<string, unknown>[] = [];
  let next: string | null = path;
  let denied = false;
  for (let page = 0; page < (opts?.pages ?? 5) && next; page++) {
    const res = await graphRequest(transport, "GET", next, { query: page === 0 ? query : undefined, sleep: opts?.sleep });
    if (res.status === 403) {
      denied = true;
      break;
    }
    if (res.status >= 400) throw new GraphError(`Graph ${res.status} ${path}`, res.status);
    records.push(...graphValues(res.body));
    const link = res.body && typeof res.body === "object" ? (res.body as { "@odata.nextLink"?: unknown })["@odata.nextLink"] : undefined;
    next = typeof link === "string" ? link : null;
  }
  return { records, denied };
}

const tokenCache = new Map<string, { value: string; exp: number }>();

async function clientToken(tenant: string, clientId: string, clientSecret: string, scope: string): Promise<string> {
  const key = `${tenant}:${clientId}:${scope}`;
  const hit = tokenCache.get(key);
  if (hit && hit.exp > Date.now() + 60_000) return hit.value;
  const res = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, scope, grant_type: "client_credentials" }),
  });
  const text = await res.text();
  if (!res.ok) throw new GraphError(`token endpoint ${res.status}: ${text.slice(0, 180)}`, res.status);
  const json = JSON.parse(text) as { access_token: string; expires_in: number };
  tokenCache.set(key, { value: json.access_token, exp: Date.now() + json.expires_in * 1000 });
  return json.access_token;
}

/** Live client-credentials transport. Graph and manage.office.com use different token scopes. */
export function liveGraphTransport(opts: { azureTenantId: string; clientId: string; clientSecret: string }): GraphTransport {
  return {
    async request(method, path, req) {
      const url = path.startsWith("http") ? new URL(path) : new URL(`https://graph.microsoft.com/v1.0${path}`);
      if (req?.query) for (const [k, v] of Object.entries(req.query)) url.searchParams.set(k, v);
      const scope = url.host.endsWith("manage.office.com") ? "https://manage.office.com/.default" : "https://graph.microsoft.com/.default";
      const token = await clientToken(opts.azureTenantId, opts.clientId, opts.clientSecret, scope);
      const res = await fetch(url, {
        method,
        headers: { authorization: `Bearer ${token}`, ...(req?.body !== undefined ? { "content-type": "application/json" } : {}) },
        body: req?.body !== undefined ? JSON.stringify(req.body) : undefined,
      });
      const text = await res.text();
      let body: unknown = {};
      if (text) {
        try {
          body = JSON.parse(text);
        } catch {
          body = { raw: text.slice(0, 300) };
        }
      }
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      return { status: res.status, headers, body };
    },
  };
}
