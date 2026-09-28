import { Agent, type Dispatcher } from "undici";

export type HttpOptions = { tlsVerify?: boolean; caPem?: string; timeoutMs?: number };

const agents = new Map<string, Dispatcher>();

/** Per-integration dispatcher so self-signed Wazuh/OpenCTI CAs can be pinned without disabling TLS globally. */
export function dispatcherFor(opts: HttpOptions): Dispatcher | undefined {
  if (opts.tlsVerify !== false && !opts.caPem) return undefined;
  const key = `${opts.tlsVerify}:${opts.caPem ?? ""}`;
  let a = agents.get(key);
  if (!a) {
    a = new Agent({ connect: { rejectUnauthorized: opts.tlsVerify !== false, ca: opts.caPem } });
    agents.set(key, a);
  }
  return a;
}

export async function httpJson<T>(
  url: string,
  init: RequestInit & { json?: unknown },
  opts: HttpOptions = {},
): Promise<T> {
  const { json, ...rest } = init;
  const res = await fetch(url, {
    ...rest,
    body: json !== undefined ? JSON.stringify(json) : rest.body,
    headers: { ...(json !== undefined ? { "content-type": "application/json" } : {}), ...rest.headers },
    signal: AbortSignal.timeout(opts.timeoutMs ?? 20_000),
    // @ts-expect-error undici dispatcher is supported by Node's fetch
    dispatcher: dispatcherFor(opts),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} from ${new URL(url).host}: ${text.slice(0, 300)}`);
  return (text ? JSON.parse(text) : {}) as T;
}
