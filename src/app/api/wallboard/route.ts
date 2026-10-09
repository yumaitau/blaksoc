import { AccessDenied } from "@/lib/auth/access";
import { logger } from "@/lib/obs/log";
import { signedWallboardSnapshot, wallboardSnapshot } from "@/lib/services/wallboard";

export const dynamic = "force-dynamic";

const response = (status: number, data: unknown) => Response.json(data, {
  status,
  headers: { "Cache-Control": "private, no-store, max-age=0", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow" },
});

/** The URL grants only this read-only summary, never access to session-authenticated APIs. */
export async function GET(request: Request) {
  try {
    const query = new URL(request.url).searchParams;
    if (query.has("token")) {
      const tokens = query.getAll("token");
      if (tokens.length !== 1 || !tokens[0]) return response(401, { error: "This display link is invalid or has expired." });
      const snapshot = await signedWallboardSnapshot(tokens[0]);
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
