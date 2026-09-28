import "server-only";
import { AccessDenied, type AccessContext } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";

export type ActionResult<T = unknown> = { ok: true; data?: T; message?: string } | { ok: false; error: string };

/**
 * Wrap a server action body: resolve the caller, map authz/validation failures to a
 * safe message, never leak stack traces to the browser.
 */
export async function withAccess<T>(fn: (ctx: AccessContext) => Promise<T>): Promise<ActionResult<T>> {
  const ctx = await currentAccess();
  if (!ctx) return { ok: false, error: "Your session has expired. Sign in again." };
  try {
    return { ok: true, data: await fn(ctx) };
  } catch (err) {
    // AccessDenied messages describe the rule that failed, never other tenants' data.
    if (err instanceof AccessDenied) return { ok: false, error: err.message && err.message !== "forbidden" ? `Not permitted: ${err.message}.` : "You don't have permission to do that." };
    if (err && typeof err === "object" && "issues" in err) return { ok: false, error: "Some fields are invalid." };
    console.error("[action]", err);
    // Database/driver errors carry a code and may describe internals; show a generic message.
    const internal = !(err instanceof Error) || "code" in err || "cause" in err;
    return { ok: false, error: internal ? "Something went wrong. The error has been logged." : err.message };
  }
}
