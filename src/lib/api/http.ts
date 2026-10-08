import { z } from "zod";
import { systemDb } from "@/db/client";
import { AccessDenied, can, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { sharedRateLimitStore, type RateRule } from "@/lib/auth/rate-limit";
import { audit } from "@/lib/audit";
import { env } from "@/lib/env";
import { clientIpFromForwarded, parseTrustedProxies } from "@/lib/net/client-ip";
import { redis } from "@/lib/redis";
import { KelpieManaged } from "@/lib/services/kelpie";
import { authenticateServiceToken } from "@/lib/services/service-identities";
import { logger } from "@/lib/obs/log";
import { TuningRefused } from "@/lib/tuning/errors";
import { parseBearer } from "./tokens";

/** Per service identity, across replicas. */
export const API_RATE: RateRule = { window: 60, max: 300 };
/** Per client id at the token endpoint: slows secret guessing and token churn. */
export const TOKEN_RATE: RateRule = { window: 60, max: 20 };

let store: ReturnType<typeof sharedRateLimitStore> | undefined;
export function rateStore() {
  store ??= sharedRateLimitStore(redis, (err) => logger.warn("api rate limit fell back to per-process counting", { err }));
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
    res = await idempotent(req, caller.identity.id, () => fn(caller.ctx));
  } catch (err) {
    if (err instanceof NotFound) res = json(404, { error: "not_found" });
    // AccessDenied messages name the rule that failed, never another tenant's data.
    else if (err instanceof AccessDenied) res = json(403, { error: "insufficient_scope", message: err.message });
    else if (err instanceof z.ZodError) res = json(400, { error: "invalid_request", issues: err.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    else if (err instanceof SyntaxError) res = json(400, { error: "invalid_request", message: "body must be JSON" });
    else if (err instanceof KelpieManaged) res = json(409, { error: "conflict", message: err.message });
    else if (err instanceof TuningRefused) {
      const retry = typeof err.extra.retryAfter === "number" ? { "retry-after": String(err.extra.retryAfter) } : undefined;
      res = json(err.status, { error: err.error, message: err.message, ...err.extra }, retry);
    }
    else {
      logger.error("api request failed", { err });
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

const IDEMPOTENCY_KEY = /^[A-Za-z0-9_.:-]{1,200}$/;
const IDEMPOTENCY_TTL = 24 * 3600;
const within = <T>(p: Promise<T>, ms = 500) =>
  Promise.race([p, new Promise<never>((_, reject) => setTimeout(() => reject(new Error("redis timeout")), ms).unref?.())]);

/**
 * `Idempotency-Key` on tuning writes: a successful answer is kept for 24 hours per identity, path and key, and a
 * retry with the same key gets it back instead of acting twice. Best effort: without Redis the call simply runs.
 */
async function idempotent(req: Request, identityId: string, run: () => Promise<Response>): Promise<Response> {
  const key = req.headers.get("idempotency-key");
  const path = new URL(req.url).pathname;
  if (!key || req.method === "GET" || !path.startsWith("/api/v1/tuning/") || !IDEMPOTENCY_KEY.test(key)) return run();
  const k = `blaksoc:idem:${identityId}:${req.method}:${path}:${key}`;
  try {
    const hit = await within(redis().get(k));
    if (hit) {
      const saved = JSON.parse(hit) as { status: number; body: unknown };
      return json(saved.status, saved.body, { "idempotent-replayed": "true" });
    }
  } catch {
    // Redis unavailable: run without replay protection.
  }
  const res = await run();
  if (res.status < 300) {
    await within(res.clone().json().then((body) => redis().set(k, JSON.stringify({ status: res.status, body }), "EX", IDEMPOTENCY_TTL))).catch(() => undefined);
  }
  return res;
}

/** Request body as JSON, refusing anything over `maxBytes` before parsing it. */
export async function jsonBody(req: Request, maxBytes: number): Promise<unknown> {
  const text = await req.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new TuningRefused(`The request body is larger than ${Math.round(maxBytes / 1024)} KB.`, 413);
  return JSON.parse(text);
}

/** 403 before any work (or rate budget) is spent when the token lacks the scope everywhere. */
export function requireScope(ctx: AccessContext, scope: Permission): void {
  if (!can(ctx, scope)) throw new AccessDenied(`missing ${scope}`);
}

/** Per-identity hourly budgets for the tuning API, on top of API_RATE. */
export const TUNING_RATES = {
  read: { window: 3600, max: 120 },
  annotate: { window: 3600, max: 600 },
  act: { window: 3600, max: 60 },
  report: { window: 3600, max: 30 },
  memory: { window: 3600, max: 120 },
} satisfies Record<string, RateRule>;

export async function tuningRate(ctx: AccessContext, bucket: keyof typeof TUNING_RATES): Promise<void> {
  const rule = TUNING_RATES[bucket];
  const r = await rateStore().consume(`api-tuning:${bucket}:${ctx.principal.userId}`, rule);
  if (!r.allowed) throw new TuningRefused(`Too many ${bucket} requests; try again later.`, 429, "rate_limited", { retryAfter: r.retryAfter ?? rule.window });
}
