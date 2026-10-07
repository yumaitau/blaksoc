import type { Instrumentation } from "next";

/** Runs once per server start. Tracing, metrics and the metrics port are Node-only. */
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await import("./instrumentation.node");
}

/** Server errors from renders, route handlers, actions and the proxy, as one structured line each. */
export const onRequestError: Instrumentation.onRequestError = async (err, request, context) => {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  const { logger } = await import("@/lib/obs/log");
  const id = request.headers["x-request-id"];
  logger.error("request failed", {
    requestId: Array.isArray(id) ? id[0] : id,
    method: request.method,
    // The query string can carry tokens (OAuth callbacks); the path is enough to find the route.
    path: request.path.split("?")[0],
    route: context.routePath,
    routeType: context.routeType,
    digest: err && typeof err === "object" && "digest" in err ? String(err.digest) : undefined,
    err,
  });
};
