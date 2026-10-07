import { env } from "@/lib/env";
import { clientIpFromForwarded, parseTrustedProxies } from "@/lib/net/client-ip";
import { withObsContext } from "@/lib/obs/context";
import { logger } from "@/lib/obs/log";
import { syslogLines } from "@/lib/obs/metrics";
import { REQUEST_ID_HEADER, requestIdFrom } from "@/lib/obs/request-id";
import { acceptSyslog, SyslogError } from "@/lib/services/syslog";

export const dynamic = "force-dynamic";

/**
 * The sender's address for the source allowlist. Never the leftmost X-Forwarded-For entry, which
 * the client controls. An empty result fails the allowlist check (sources without one are unaffected).
 */
function sourceIp(req: Request): string {
  return clientIpFromForwarded(req.headers.get("x-forwarded-for"), parseTrustedProxies(env().TRUSTED_PROXY_CIDRS)) ?? "";
}

/** TLS syslog sink. Vector, or the firewall itself, posts lines with a per-tenant bearer token. */
export async function POST(req: Request) {
  // Not behind the session proxy, so the id is assigned here.
  const requestId = requestIdFrom(req.headers);
  const res = await withObsContext({ requestId }, () => accept(req));
  res.headers.set(REQUEST_ID_HEADER, requestId);
  return res;
}

async function accept(req: Request): Promise<Response> {
  if (req.headers.get("x-forwarded-proto") === "http") {
    return Response.json({ error: "tls" }, { status: 400 });
  }
  const header = req.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  if (!match) return Response.json({ error: "token" }, { status: 401 });
  const body = await req.text();
  if (body.length > 800_000) return Response.json({ error: "size" }, { status: 413 });
  try {
    const result = await acceptSyslog({ token: match[1]!, sourceIp: sourceIp(req), body });
    syslogLines().inc({ outcome: "accepted" }, result.accepted);
    syslogLines().inc({ outcome: "rejected" }, result.rejected);
    return Response.json(result, { status: 202 });
  } catch (err) {
    if (err instanceof SyslogError) {
      const status = err.code === "token" ? 401 : err.code === "source-ip" ? 403 : 400;
      logger.warn("syslog post refused", { reason: err.code, status });
      return Response.json({ error: err.code }, { status });
    }
    logger.error("syslog ingest failed", { err });
    throw err;
  }
}
