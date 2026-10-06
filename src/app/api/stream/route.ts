import { sessionStateFor } from "@/lib/auth/session";
import { eventVisible, subscribe } from "@/lib/events";

export const dynamic = "force-dynamic";

/** How often an open stream re-checks the session and the viewer's roles. */
const RECHECK_MS = 60_000;

/**
 * Server-Sent Events for live SOC updates, filtered server-side per viewer. The stream re-reads
 * the session and roles every minute, so a revoked role, disabled user or ended session stops
 * receiving events without waiting for the browser to disconnect.
 */
export async function GET(req: Request) {
  const first = await sessionStateFor(req.headers);
  if (first.state !== "ok") return new Response("unauthorised", { status: 401 });
  let ctx = first.access;

  const encoder = new TextEncoder();
  let unsubscribe = () => {};
  let ping: ReturnType<typeof setInterval> | undefined;
  let recheck: ReturnType<typeof setInterval> | undefined;
  const stream = new ReadableStream({
    start(controller) {
      const stop = () => {
        clearInterval(ping);
        clearInterval(recheck);
        unsubscribe();
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };
      const send = (s: string) => {
        try {
          controller.enqueue(encoder.encode(s));
        } catch {
          /* closed */
        }
      };
      send("retry: 5000\n\n");
      unsubscribe = subscribe((e) => {
        if (eventVisible(ctx, e)) send(`event: soc\ndata: ${JSON.stringify(e)}\n\n`);
      });
      ping = setInterval(() => send(": ping\n\n"), 25_000);
      recheck = setInterval(() => {
        sessionStateFor(req.headers)
          .then((state) => {
            if (state.state === "ok") ctx = state.access;
            else stop();
          })
          .catch(() => stop());
      }, RECHECK_MS);
      req.signal.addEventListener("abort", stop);
    },
    cancel() {
      clearInterval(ping);
      clearInterval(recheck);
      unsubscribe();
    },
  });
  return new Response(stream, { headers: { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", connection: "keep-alive", "x-accel-buffering": "no" } });
}
