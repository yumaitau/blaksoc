import { and, eq, inArray, isNull, or } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { integrations, tenants } from "@/db/schema";
import { env } from "@/lib/env";
import type { SocEvent } from "@/lib/events";
import { queue, QUEUES } from "@/lib/queue";
import { notifier } from "./instances";
import type { Notification } from "./notify";

/** Categories whose connectors take `events` subscriptions (webhook, Teams, Slack). */
const SUBSCRIBER_CATEGORIES = ["collaboration", "ticketing"];

/** True when an integration's config subscribes it to `eventType`. */
export function subscribesTo(config: unknown, eventType: string): boolean {
  const events = (config as { events?: unknown } | null)?.events;
  return Array.isArray(events) && events.includes(eventType);
}

const PATHS: Record<SocEvent["type"], (e: SocEvent) => string> = {
  "alert.created": (e) => `/soc/alerts/${e.id}`,
  "alert.updated": (e) => `/soc/alerts/${e.id}`,
  "incident.created": (e) => `/soc/incidents/${e.id}`,
  "incident.updated": (e) => `/soc/incidents/${e.id}`,
  "approval.requested": () => "/soc/approvals",
  "response.updated": () => "/soc/approvals",
};

/** The notification a subscriber receives for a bus event. Carries ids and titles, never raw telemetry. */
export function eventNotification(e: SocEvent, tenantName: string, appUrl: string): Notification {
  const base = { event: e.type, tenant: { id: e.tenantId, name: tenantName }, url: `${appUrl}${PATHS[e.type](e)}` };
  switch (e.type) {
    case "alert.created":
      return { ...base, title: e.title, severity: e.severity, summary: `New alert, risk ${e.riskScore}.` };
    case "incident.created":
      return { ...base, title: e.title, severity: e.severity, summary: "New incident opened." };
    case "approval.requested":
      return { ...base, title: `Approval needed: ${e.summary}`, summary: "A response action is waiting for a human decision." };
    case "alert.updated":
      return { ...base, title: "Alert updated", summary: `Status ${e.status}.` };
    case "incident.updated":
      return { ...base, title: "Incident updated", summary: "The incident changed." };
    case "response.updated":
      return { ...base, title: "Response action updated", summary: `Status ${e.status}.` };
  }
}

const CACHE_MS = 60_000;
let cached: { at: number; types: Set<string> } | null = null;

/** Event types any enabled subscriber wants. Cached so publish() does not query per alert. */
export async function subscribedEventTypes(now = Date.now()): Promise<Set<string>> {
  if (cached && now - cached.at < CACHE_MS) return cached.types;
  const rows = await systemDb().select({ config: integrations.config }).from(integrations).where(and(eq(integrations.enabled, true), inArray(integrations.category, SUBSCRIBER_CATEGORIES)));
  const types = new Set<string>();
  for (const row of rows) {
    const events = (row.config as { events?: unknown }).events;
    if (Array.isArray(events)) events.forEach((t) => typeof t === "string" && types.add(t));
  }
  cached = { at: now, types };
  return types;
}

/** Worker: one delivery job per subscribed integration, so each retries on its own. */
export async function fanOutEvent(e: SocEvent): Promise<{ queued: number }> {
  const rows = await systemDb()
    .select({ id: integrations.id, config: integrations.config })
    .from(integrations)
    .where(and(eq(integrations.enabled, true), inArray(integrations.category, SUBSCRIBER_CATEGORIES), or(eq(integrations.tenantId, e.tenantId), isNull(integrations.tenantId))));
  const targets = rows.filter((row) => subscribesTo(row.config, e.type));
  if (!targets.length) return { queued: 0 };
  const [tenant] = await systemDb().select({ name: tenants.name }).from(tenants).where(eq(tenants.id, e.tenantId));
  const notification = eventNotification(e, tenant?.name ?? "", env().APP_URL);
  for (const target of targets) await queue(QUEUES.notify).add("deliver", { integrationId: target.id, notification });
  return { queued: targets.length };
}

/** Worker: send one notification. Throws on failure so BullMQ retries with backoff and keeps the failed job. */
export async function deliverToIntegration(integrationId: string, notification: Notification): Promise<void> {
  const [row] = await systemDb().select().from(integrations).where(eq(integrations.id, integrationId));
  if (!row || !row.enabled) return;
  const target = notifier(row);
  if (!target) return;
  await target.send(notification);
}
