import { acceptSyslog, SyslogError } from "@/lib/services/syslog";

export const dynamic = "force-dynamic";

function sourceIp(req: Request): string {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0]!.trim();
  return req.headers.get("x-real-ip")?.trim() ?? "";
}

/** TLS syslog sink. Vector, or the firewall itself, posts lines with a per-tenant bearer token. */
export async function POST(req: Request) {
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
    return Response.json(result, { status: 202 });
  } catch (err) {
    if (err instanceof SyslogError) {
      const status = err.code === "token" ? 401 : err.code === "source-ip" ? 403 : 400;
      return Response.json({ error: err.code }, { status });
    }
    throw err;
  }
}
