import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import type { NormalisedAlert, SecurityEventProvider } from "./types";

export const WEDGETAIL_BODY_LIMIT = 256 * 1024;
const text = z.string().min(1).max(4096);
const identifier = z.string().min(1).max(256);
const date = z.iso.datetime({ offset: true });
const severity = z.enum(["informational", "low", "medium", "high", "critical"]);
const techniques = z.array(z.string().regex(/^T\d{4}(?:\.\d{3})?$/)).max(100);
const refs = z.array(text).max(100);
const entities = z.array(z.object({ type: text, value: text, field: text.optional() })).max(100);
const nullableText = text.nullable().optional();
const summary = z.object({
  schema: z.literal("wedgetail.alert.v1"),
  alert: z.object({ id: identifier, ruleId: identifier, title: text, description: z.string().max(20000).optional(), severity, detectedAt: date, classification: text.optional(), url: z.string().url().optional(), mitre: techniques.optional(), ism: refs.optional(), essentialEight: refs.optional() }),
  entities: z.object({ principal: nullableText, ip: nullableText, resource: nullableText, account: nullableText, model: nullableText, domain: nullableText, host: nullableText }),
  mitre: techniques.optional(), ism: refs.optional(), essentialEight: refs.optional(),
});
const created = z.object({
  type: z.literal("wedgetail.alert.created"),
  alert: z.object({ id: identifier, ruleId: identifier, ruleTitle: text, description: z.string().max(20000).optional(), severity, firstSeen: date, updatedAt: date.optional(), entities, mitre: techniques, ism: refs, essentialEight: refs, accountId: text.optional(), region: text.optional(), eventCount: z.number().int().nonnegative().optional() }),
  url: z.string().url().optional(),
});
export const WEDGETAIL_STATUSES = {
  new: "NEW", reopened: "NEW", acknowledged: "TRIAGING", in_progress: "INVESTIGATING",
  closed: "RESOLVED", closed_true_positive: "RESOLVED", closed_benign: "RESOLVED", closed_false_positive: "FALSE_POSITIVE",
} as const;
const updated = z.object({
  type: z.literal("wedgetail.alert.updated"),
  alert: z.object({ id: identifier, status: z.enum(Object.keys(WEDGETAIL_STATUSES) as [keyof typeof WEDGETAIL_STATUSES, ...(keyof typeof WEDGETAIL_STATUSES)[]]), updatedAt: date }),
});
export const wedgetailEvent = z.union([updated, created, summary]);
/** Other signed Wedgetail notices are acknowledged without validating or retaining their contents. */
export const unhandledWedgetailEvent = z.object({
  type: z.string().regex(/^wedgetail\.(?!(?:alert\.created|alert\.updated)$)/),
});
export type WedgetailEvent = z.infer<typeof wedgetailEvent>;
export type WedgetailUpdate = z.infer<typeof updated>;

/** Same scheme as Wedgetail engine/src/notify/payloads.ts; sign exact bytes, never reserialised JSON. */
export function verifyWedgetail(body: Uint8Array, headers: Headers, secret: string, now = Date.now()): boolean {
  const timestamp = headers.get("x-wedgetail-timestamp");
  if (!secret || !timestamp || !/^\d{10,12}$/.test(timestamp) || Math.abs(now / 1000 - Number(timestamp)) > 300) return false;
  const expected = Buffer.from(`v1=${createHmac("sha256", secret).update(`${timestamp}.`).update(body).digest("hex")}`);
  const received = Buffer.from(headers.get("x-wedgetail-signature") ?? "");
  return received.length === expected.length && timingSafeEqual(received, expected);
}

export function normaliseWedgetail(event: Exclude<WedgetailEvent, WedgetailUpdate>): NormalisedAlert {
  const a = event.alert;
  const generic = "type" in event;
  const list = generic ? event.alert.entities : Object.entries(event.entities).filter(([, value]) => value != null).map(([type, value]) => ({ type, value: value! }));
  const first = (type: string) => list.find((e) => e.type === type)?.value ?? null;
  const mitre = generic ? event.alert.mitre : event.alert.mitre ?? event.mitre ?? (event.alert.classification?.match(/^T\d{4}(?:\.\d{3})?$/) ? [event.alert.classification] : []);
  const title = generic ? event.alert.ruleTitle : event.alert.title;
  const occurredAt = generic ? event.alert.firstSeen : event.alert.detectedAt;
  // Keep IPs, ARNs and compliance references in raw for extraction, evidence and future cloud mappings.
  return {
    externalId: a.id, ruleId: a.ruleId, title, description: a.description ?? null, severity: a.severity,
    siemSeverity: null, category: "aws", occurredAt: new Date(occurredAt), assetExternalId: first("resource"),
    hostname: first("host"), userName: first("principal"), attackTechniques: mitre, routingKeys: [],
    raw: { schema: "wedgetail.alert.v1", ...a, entities: list, sourceIp: first("ip"), principalArn: first("principal"), resourceArn: first("resource"), mitre,
      ism: generic ? event.alert.ism : event.alert.ism ?? event.ism ?? [],
      essentialEight: generic ? event.alert.essentialEight : event.alert.essentialEight ?? event.essentialEight ?? [],
      url: generic ? event.url : event.alert.url },
  };
}

/** Push-only provider: polling never opens a connection to the customer's AWS account. */
export class WedgetailProvider implements SecurityEventProvider {
  readonly kind = "wedgetail";
  async getAlerts() { return { alerts: [], cursor: null }; }
  async getAlert() { return null; }
  async searchEvents() { return { total: 0, events: [] }; }
  async getAssets() { return []; }
  async getAsset() { return null; }
  supportedActions() { return []; }
  async executeResponseAction() { return { ok: false, message: "Wedgetail is an inbound webhook provider" }; }
  async health() { return { ok: true, latencyMs: 0, detail: { note: "Health is measured by inbound deliveries" } }; }
}
