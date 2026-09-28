import { can } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { subscribe, type SocEvent } from "@/lib/events";

export const dynamic = "force-dynamic";

/**
 * Server-Sent Events for live SOC updates. Events are filtered server-side to tenants the
 * viewer may read; customers only receive incident/response events for their own tenant.
 */
export async function GET(req: Request) {
  const ctx = await currentAccess();
  if (!ctx) return new Response("unauthorised", { status: 401 });
  const allowed = new Set(ctx.tenantIds);

  const visible = (e: SocEvent) => {
    if (!allowed.has(e.tenantId)) return false;
    if (e.type.startsWith("alert.") || e.type === "approval.requested") return can(ctx, "alert:read", e.tenantId) && ctx.isPlatform;
    return can(ctx, "incident:read", e.tenantId);
  };

  const encoder = new TextEncoder();
  let unsubscribe = () => {};
  let ping: ReturnType<typeof setInterval> | undefined;
  const stream = new ReadableStream({
    start(controller) {
      const send = (s: string) => {
        try {
          controller.enqueue(encoder.encode(s));
        } catch {
          /* closed */
        }
      };
      send("retry: 5000\n\n");
      unsubscribe = subscribe((e) => {
        if (visible(e)) send(`event: soc\ndata: ${JSON.stringify(e)}\n\n`);
      });
      ping = setInterval(() => send(": ping\n\n"), 25_000);
      req.signal.addEventListener("abort", () => {
        clearInterval(ping);
        unsubscribe();
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      });
    },
    cancel() {
      clearInterval(ping);
      unsubscribe();
    },
  });
  return new Response(stream, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", connection: "keep-alive", "x-accel-buffering": "no" } });
}
