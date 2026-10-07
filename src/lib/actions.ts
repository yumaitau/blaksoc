import "server-only";
import { headers } from "next/headers";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { withObsContext } from "@/lib/obs/context";
import { logger } from "@/lib/obs/log";
import { REQUEST_ID_HEADER } from "@/lib/obs/request-id";

export type ActionResult<T = unknown> = { ok: true; data?: T; message?: string } | { ok: false; error: string };

/** The proxy stamps every app request; outside a request (tests, scripts) there is none. */
async function requestId(): Promise<string | undefined> {
  try {
    return (await headers()).get(REQUEST_ID_HEADER) ?? undefined;
  } catch {
    return undefined;
  }
}

/**
 * Wrap a server action body: resolve the caller, map authz/validation failures to a
 * safe message, never leak stack traces to the browser. The body runs in a log context carrying
 * the request id, which also rides along on any job it enqueues.
 */
export async function withAccess<T>(fn: (ctx: AccessContext) => Promise<T>): Promise<ActionResult<T>> {
  const ctx = await currentAccess();
  if (!ctx) return { ok: false, error: "Your session has expired. Sign in again." };
  return withObsContext({ requestId: await requestId() }, async () => {
    try {
      return { ok: true as const, data: await fn(ctx) };
    } catch (err) {
      // AccessDenied messages describe the rule that failed, never other tenants' data.
      if (err instanceof AccessDenied) return { ok: false as const, error: err.message && err.message !== "forbidden" ? `Not permitted: ${err.message}.` : "You don't have permission to do that." };
      if (err && typeof err === "object" && "issues" in err) return { ok: false as const, error: "Some fields are invalid." };
      logger.error("server action failed", { userId: ctx.principal.userId, err });
      // Database/driver errors carry a code and may describe internals; show a generic message.
      const internal = !(err instanceof Error) || "code" in err || "cause" in err;
      return { ok: false as const, error: internal ? "Something went wrong. The error has been logged." : err.message };
    }
  });
}
