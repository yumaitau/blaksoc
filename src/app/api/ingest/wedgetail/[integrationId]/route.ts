import { sharedRateLimitStore } from "@/lib/auth/rate-limit";
import { withObsContext } from "@/lib/obs/context";
import { logger } from "@/lib/obs/log";
import { REQUEST_ID_HEADER, requestIdFrom } from "@/lib/obs/request-id";
import { WEDGETAIL_BODY_LIMIT } from "@/lib/providers/wedgetail";
import { redis } from "@/lib/redis";
import { acceptWedgetail, recordWedgetailOutcome, wedgetailIntegration, WedgetailError } from "@/lib/services/wedgetail";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
const limiter = sharedRateLimitStore(redis, () => logger.warn("wedgetail rate limit using local fallback"));

/** Bound memory while reading chunked bodies too; Content-Length is only an early refusal. */
async function readBody(req: Request): Promise<Uint8Array> {
  if (Number(req.headers.get("content-length")) > WEDGETAIL_BODY_LIMIT) throw new WedgetailError(413, "size");
  const reader = req.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > WEDGETAIL_BODY_LIMIT) {
        await reader.cancel();
        throw new WedgetailError(413, "size");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks, size);
}

export async function POST(req: Request, { params }: { params: Promise<{ integrationId: string }> }) {
  const requestId = requestIdFrom(req.headers);
  const { integrationId } = await params;
  const response = await withObsContext({ requestId }, async () => {
    if (req.headers.get("x-forwarded-proto") === "http") return Response.json({ error: "tls" }, { status: 400 });
    // Invalid IDs share a bucket; never use attacker-chosen paths as metric labels.
    const key = /^[0-9a-f-]{36}$/i.test(integrationId) ? integrationId.toLowerCase() : "unknown";
    const rate = await limiter.consume(`wedgetail:${key}`, { window: 60, max: 300 });
    if (!rate.allowed) return Response.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": String(rate.retryAfter ?? 60) } });
    let row: Awaited<ReturnType<typeof wedgetailIntegration>> = null;
    try {
      row = await wedgetailIntegration(integrationId);
      if (!row) {
        await recordWedgetailOutcome(null, "rejected");
        return Response.json({ error: "not_found" }, { status: 404 });
      }
      const result = await acceptWedgetail(row, await readBody(req), req.headers);
      return Response.json(result, { status: result.outcome === "created" ? 202 : 200 });
    } catch (err) {
      if (err instanceof WedgetailError) {
        if (err.code !== "unrouted") await recordWedgetailOutcome(row, "rejected").catch(() => logger.warn("wedgetail rejected count unavailable"));
        logger.warn("wedgetail post refused", { reason: err.code, status: err.status });
        return Response.json({ error: err.code }, { status: err.status });
      }
      // Exceptions may contain vendor data; log only the fixed failure category.
      logger.error("wedgetail ingest failed");
      return Response.json({ error: "unavailable" }, { status: 503 });
    }
  });
  response.headers.set(REQUEST_ID_HEADER, requestId);
  response.headers.set("Cache-Control", "no-store");
  return response;
}
