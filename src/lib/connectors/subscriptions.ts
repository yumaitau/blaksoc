import { and, eq, inArray, isNull, or } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { integrations, tenants } from "@/db/schema";
import { env } from "@/lib/env";
import type { SocEvent } from "@/lib/events";
import { queue, QUEUES } from "@/lib/queue";
import { redis } from "@/lib/redis";
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
/** How often a process reads the shared version. Bounds both Redis reads on the publish path and refresh delay. */
const VERSION_CHECK_MS = 5_000;
const VERSION_KEY = "blaksoc:subscriptions:version";
let cached: { at: number; checkedAt: number; version: string; types: Set<string> } | null = null;
let refreshing: Promise<Set<string>> | null = null;

/**
 * Call after creating, changing, enabling or disabling a webhook, Teams or Slack integration.
 * Every process's subscribedEventTypes() cache refreshes within VERSION_CHECK_MS.
 */
export async function subscriptionsChanged(): Promise<void> {
  await redis().incr(VERSION_KEY);
}

/**
 * Event types any enabled subscriber wants. Cached so publish() does not query Postgres per alert.
 * The shared version is read at most every VERSION_CHECK_MS; Postgres is read again when the
 * version changed or after CACHE_MS.
 */
export async function subscribedEventTypes(now = Date.now()): Promise<Set<string>> {
  if (cached && now - cached.checkedAt < VERSION_CHECK_MS && now - cached.at < CACHE_MS) return cached.types;
  // Events arriving together after the interval share one refresh instead of each reading Redis and Postgres.
  refreshing ??= refreshSubscribedTypes(now).finally(() => {
    refreshing = null;
  });
  return refreshing;
}

async function refreshSubscribedTypes(now: number): Promise<Set<string>> {
  const version = (await redis().get(VERSION_KEY)) ?? "0";
  if (cached && cached.version === version && now - cached.at < CACHE_MS) {
    cached.checkedAt = now;
    return cached.types;
  }
  const rows = await systemDb().select({ config: integrations.config }).from(integrations).where(and(eq(integrations.enabled, true), inArray(integrations.category, SUBSCRIBER_CATEGORIES)));
  const types = new Set<string>();
  for (const row of rows) {
    const events = (row.config as { events?: unknown }).events;
    if (Array.isArray(events)) events.forEach((t) => typeof t === "string" && types.add(t));
  }
  cached = { at: now, checkedAt: now, version, types };
  return types;
}

/**
 * The event carried by a notify `event` job, whichever release queued it: a bare SocEvent (before
 * event ids), `{ event, eventId }` (PR #112), or `{ ...event, eventId }` (current). Jobs without an
 * id use the BullMQ job id, which is stable across that job's retries.
 */
export function eventJobPayload(data: Record<string, unknown>, jobId: string): { event: SocEvent; eventId: string } {
  const { eventId, event: nested, ...flat } = data;
  const event = (nested && typeof nested === "object" ? nested : flat) as SocEvent;
  return { event, eventId: typeof eventId === "string" && eventId ? eventId : jobId };
}

/**
 * Worker: one delivery job per subscribed integration, so each retries on its own. Job ids are
 * derived from the event id, so retrying this fan-out never queues a second delivery.
 */
export async function fanOutEvent(e: SocEvent, eventId: string): Promise<{ queued: number }> {
  const rows = await systemDb()
    .select({ id: integrations.id, config: integrations.config })
    .from(integrations)
    .where(and(eq(integrations.enabled, true), inArray(integrations.category, SUBSCRIBER_CATEGORIES), or(eq(integrations.tenantId, e.tenantId), isNull(integrations.tenantId))));
  const targets = rows.filter((row) => subscribesTo(row.config, e.type));
  if (!targets.length) return { queued: 0 };
  const [tenant] = await systemDb().select({ name: tenants.name }).from(tenants).where(eq(tenants.id, e.tenantId));
  const notification = eventNotification(e, tenant?.name ?? "", env().APP_URL);
  for (const target of targets) await queue(QUEUES.notify).add("deliver", { integrationId: target.id, notification }, { jobId: deliveryJobId(eventId, target.id) });
  return { queued: targets.length };
}

/** BullMQ ignores an add whose job id already exists, which makes delivery idempotent per event and integration. */
export function deliveryJobId(eventId: string, integrationId: string): string {
  return `deliver-${eventId}-${integrationId}`;
}

/** Worker: send one notification. Throws on failure so BullMQ retries with backoff and keeps the failed job. */
export async function deliverToIntegration(integrationId: string, notification: Notification): Promise<void> {
  const [row] = await systemDb().select().from(integrations).where(eq(integrations.id, integrationId));
  if (!row || !row.enabled) return;
  const target = notifier(row);
  if (!target) return;
  await target.send(notification);
}
