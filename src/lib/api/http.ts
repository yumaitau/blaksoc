import { z } from "zod";
import { systemDb } from "@/db/client";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import { sharedRateLimitStore, type RateRule } from "@/lib/auth/rate-limit";
import { audit } from "@/lib/audit";
import { env } from "@/lib/env";
import { clientIpFromForwarded, parseTrustedProxies } from "@/lib/net/client-ip";
import { redis } from "@/lib/redis";
import { KelpieManaged } from "@/lib/services/kelpie";
import { authenticateServiceToken } from "@/lib/services/service-identities";
import { parseBearer } from "./tokens";

/** Per service identity, across replicas. */
export const API_RATE: RateRule = { window: 60, max: 300 };
/** Per client id at the token endpoint: slows secret guessing and token churn. */
export const TOKEN_RATE: RateRule = { window: 60, max: 20 };

let store: ReturnType<typeof sharedRateLimitStore> | undefined;
export function rateStore() {
  store ??= sharedRateLimitStore(redis, (err) => console.warn(`[api] rate limit fell back to per-process counting: ${err instanceof Error ? err.message : err}`));
  return store;
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers: { "cache-control": "no-store", ...headers } });
}

export class NotFound extends Error {}

export function clientIp(req: Request): string | null {
  return clientIpFromForwarded(req.headers.get("x-forwarded-for"), parseTrustedProxies(env().TRUSTED_PROXY_CIDRS));
}

/** Dates to ISO strings, then the schema drops anything it does not declare. */
export function shape<T extends z.ZodType>(schema: T, value: unknown): z.output<T> {
  return schema.parse(JSON.parse(JSON.stringify(value)));
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A malformed id can match nothing; answer 404 before it reaches Postgres. */
export function idParam(id: string): string {
  if (!UUID.test(id)) throw new NotFound();
  return id;
}

/**
 * Wraps a /api/v1 handler: bearer token → service AccessContext, per-identity rate limit, error
 * mapping, then one audit row per call with the identity as actor. `route` is the OpenAPI path.
 * Rate-limited calls are not audited, so a flood cannot also flood the audit chain.
 */
export async function serviceCall(req: Request, route: string, fn: (ctx: AccessContext) => Promise<Response>): Promise<Response> {
  const token = parseBearer(req.headers.get("authorization"));
  const caller = token ? await authenticateServiceToken(token) : null;
  if (!caller) return json(401, { error: "invalid_token" }, { "www-authenticate": 'Bearer error="invalid_token"' });
  const rate = await rateStore().consume(`api:${caller.identity.id}`, API_RATE);
  if (!rate.allowed) return json(429, { error: "rate_limited" }, { "retry-after": String(rate.retryAfter ?? API_RATE.window) });

  let res: Response;
  try {
    res = await fn(caller.ctx);
  } catch (err) {
    if (err instanceof NotFound) res = json(404, { error: "not_found" });
    // AccessDenied messages name the rule that failed, never another tenant's data.
    else if (err instanceof AccessDenied) res = json(403, { error: "insufficient_scope", message: err.message });
    else if (err instanceof z.ZodError) res = json(400, { error: "invalid_request", issues: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    else if (err instanceof SyntaxError) res = json(400, { error: "invalid_request", message: "body must be JSON" });
    else if (err instanceof KelpieManaged) res = json(409, { error: "conflict", message: err.message });
    else {
      console.error("[api]", err);
      res = json(500, { error: "server_error" });
    }
  }
  const url = new URL(req.url);
  await audit(systemDb(), {
    actorId: caller.identity.id,
    actorKind: "service",
    tenantId: caller.identity.tenantId,
    action: "api.request",
    targetType: "api_route",
    targetId: `${req.method} ${route}`,
    ip: clientIp(req),
    detail: { path: url.pathname, ...(url.search ? { query: url.search } : {}), status: res.status },
  });
  return res;
}
