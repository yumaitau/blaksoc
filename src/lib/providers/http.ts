import { egressFetch, type Reach } from "@/lib/net/egress";

/**
 * TLS can pin a self-signed Wazuh/OpenCTI CA per integration without disabling verification
 * globally. `reach` defaults to internal: these are self-hosted services that may sit on a
 * private network. Metadata and link-local addresses are refused either way.
 */
export type HttpOptions = { tlsVerify?: boolean; caPem?: string; timeoutMs?: number; reach?: Reach };

export async function httpJson<T>(
  url: string,
  init: RequestInit & { json?: unknown },
  opts: HttpOptions = {},
): Promise<T> {
  const { json, ...rest } = init;
  const res = await egressFetch(
    url,
    {
      ...rest,
      body: json !== undefined ? JSON.stringify(json) : rest.body,
      headers: { ...(json !== undefined ? { "content-type": "application/json" } : {}), ...rest.headers },
      signal: AbortSignal.timeout(opts.timeoutMs ?? 20_000),
    },
    opts.reach ?? "internal",
    { tlsVerify: opts.tlsVerify, caPem: opts.caPem },
  );
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} from ${new URL(url).host}: ${text.slice(0, 300)}`);
  return (text ? JSON.parse(text) : {}) as T;
}
