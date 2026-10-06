import { can, type AccessContext } from "./auth/access";
import { queue, QUEUES } from "./queue";
import { newRedis, redis } from "./redis";

/** Live SOC events. Every event carries tenantId; the SSE endpoint filters by the viewer's scope. */
export type SocEvent =
  | { type: "alert.created"; tenantId: string; id: string; title: string; severity: string; riskScore: number }
  | { type: "alert.updated"; tenantId: string; id: string; status: string }
  | { type: "incident.created"; tenantId: string; id: string; title: string; severity: string }
  | { type: "incident.updated"; tenantId: string; id: string }
  | { type: "approval.requested"; tenantId: string; id: string; summary: string }
  | { type: "response.updated"; tenantId: string; id: string; status: string };

const CHANNEL = "blaksoc:events";

/**
 * Live update for open SSE streams (lossy pub/sub), plus a durable notify job when a webhook,
 * Teams or Slack integration subscribes to this event type.
 */
export async function publish(event: SocEvent): Promise<void> {
  await redis().publish(CHANNEL, JSON.stringify(event));
  try {
    const { subscribedEventTypes } = await import("./connectors/subscriptions");
    if ((await subscribedEventTypes()).has(event.type)) await queue(QUEUES.notify).add("event", event);
  } catch (err) {
    console.warn(`[events] could not queue ${event.type} for subscribers: ${err instanceof Error ? err.message : err}`);
  }
}

export function subscribe(onEvent: (e: SocEvent) => void): () => void {
  const sub = newRedis();
  void sub.subscribe(CHANNEL);
  sub.on("message", (_c, msg) => {
    try {
      onEvent(JSON.parse(msg) as SocEvent);
    } catch {
      /* ignore malformed */
    }
  });
  return () => void sub.quit();
}

/** Whether a viewer with `ctx` may see `e` on the live stream. Customers only receive incident/response events for their own tenant. */
export function eventVisible(ctx: AccessContext, e: SocEvent): boolean {
  if (!ctx.tenantIds.includes(e.tenantId)) return false;
  if (e.type.startsWith("alert.") || e.type === "approval.requested") return can(ctx, "alert:read", e.tenantId) && ctx.isPlatform;
  return can(ctx, "incident:read", e.tenantId);
}
