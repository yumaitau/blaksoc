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

export async function publish(event: SocEvent): Promise<void> {
  await redis().publish(CHANNEL, JSON.stringify(event));
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
