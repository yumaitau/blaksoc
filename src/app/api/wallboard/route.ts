import { createHash } from "node:crypto";
import { AccessDenied } from "@/lib/auth/access";
import { sharedRateLimitStore, type RateRule } from "@/lib/auth/rate-limit";
import { env } from "@/lib/env";
import { clientIpFromForwarded, parseTrustedProxies } from "@/lib/net/client-ip";
import { logger } from "@/lib/obs/log";
import { redis } from "@/lib/redis";
import { signedWallboardSnapshot, wallboardSnapshot } from "@/lib/services/wallboard";

export const dynamic = "force-dynamic";

/** One office display polls twice a minute. This caps a leaked link and a single-address flood. */
const TOKEN_RATE: RateRule = { window: 60, max: 120 };
const IP_RATE: RateRule = { window: 60, max: 300 };

let rates: ReturnType<typeof sharedRateLimitStore> | undefined;
function wallboardRates() {
  rates ??= sharedRateLimitStore(redis, (err) => logger.warn("wallboard rate limit fell back to per-process counting", { err }));
  return rates;
}

const response = (status: number, data: unknown, extra: Record<string, string> = {}) => Response.json(data, {
  status,
  headers: { "Cache-Control": "private, no-store, max-age=0", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow", ...extra },
});

const tooFast = (retryAfter: number) => response(429, { error: "This display is refreshing too quickly. It will retry shortly." }, { "retry-after": String(retryAfter) });

/** The URL grants only this read-only summary, never access to session-authenticated APIs. */
export async function GET(request: Request) {
  try {
    const query = new URL(request.url).searchParams;
    if (query.has("token")) {
      const ip = clientIpFromForwarded(request.headers.get("x-forwarded-for"), parseTrustedProxies(env().TRUSTED_PROXY_CIDRS));
      if (ip) {
        const byIp = await wallboardRates().consume(`wallboard-ip:${ip}`, IP_RATE);
        if (!byIp.allowed) return tooFast(byIp.retryAfter ?? IP_RATE.window);
      }
      const tokens = query.getAll("token");
      if (tokens.length !== 1 || !tokens[0]) return response(401, { error: "This display link is invalid or has expired." });
      const token = tokens[0];
      const byToken = await wallboardRates().consume(`wallboard:${createHash("sha256").update(token).digest("hex")}`, TOKEN_RATE);
      if (!byToken.allowed) return tooFast(byToken.retryAfter ?? TOKEN_RATE.window);
      const snapshot = await signedWallboardSnapshot(token);
      return snapshot ? response(200, snapshot) : response(401, { error: "This display link is invalid or has expired." });
    }
    const { currentAccess } = await import("@/lib/auth/session");
    const ctx = await currentAccess();
    if (!ctx) return response(401, { error: "Sign in to view this display." });
    let tenantIds: string[];
    if (query.has("tenantIds")) {
      const scopes = query.getAll("tenantIds");
      if (scopes.length !== 1 || !scopes[0]) return response(403, { error: "Choose a permitted customer scope." });
      tenantIds = scopes[0].split(",");
      if (tenantIds.some((id) => !id)) return response(403, { error: "Choose a permitted customer scope." });
    } else {
      const { currentWorkspace } = await import("@/lib/workspace");
      const workspace = await currentWorkspace(ctx);
      tenantIds = workspace.tenantIds.filter((id) => ctx.tenants.some((t) => t.id === id && t.kind === "customer"));
    }
    return response(200, await wallboardSnapshot(ctx, tenantIds));
  } catch (err) {
    if (err instanceof AccessDenied) return response(403, { error: "You do not have access to this customer scope." });
    logger.error("wallboard refresh failed", { err });
    return response(503, { error: "The display could not refresh. It will retry shortly." });
  }
}
