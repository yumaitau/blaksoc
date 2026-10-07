/**
 * Entity graph facts: pure mappings from blakSOC records (alerts, assets, intel matches) to the
 * entities, aliases and edges they assert. src/lib/graph/store.ts writes them; nothing here
 * touches the database, so ingest, asset sync and backfill all derive the same graph.
 */
import { createHash } from "node:crypto";
import { entityType } from "@/db/schema/graph";
import type { IntelMatch } from "@/db/schema/security";
import type { Observable } from "@/lib/intel/observables";
import type { Authentication, NetworkActivity } from "@/lib/ocsf/schema";

export const ENTITY_TYPES = entityType.enumValues;
export type EntityType = (typeof ENTITY_TYPES)[number];

/** Direction reads from → to. */
export const RELATIONSHIP_TYPES = [
  "alerted_on", // alert → device, user, ip, domain, url, file, email
  "logged_into", // user → device
  "has_ip", // device → ip (inventory)
  "communicated_with", // ip → ip (OCSF Network Activity)
  "indicates", // indicator → ip, domain, url, file, email
  "matched", // alert → indicator
  "attributed_to", // indicator → threat actor, campaign
  "same_as", // user → identity
] as const;
export type RelationshipType = (typeof RELATIONSHIP_TYPES)[number];
export type Provenance = "observed" | "inferred";

export type EntityRef = { type: EntityType; key: string };
export type EntityFact = EntityRef & { displayName: string; identifiers?: Record<string, unknown>; source: string; seenAt: Date; firstSeen?: Date };
export type AliasFact = { entity: EntityRef; kind: string; value: string; source: string };
export type Evidence = { type: "alert" | "asset" | "intel_match"; id: string };
export type EdgeFact = { from: EntityRef; to: EntityRef; type: RelationshipType; provenance: Provenance; evidence: Evidence; seenAt: Date };
/** `existing`: entities found by lookup that edges point at. Linked, never updated; edges to them are dropped if they are gone. */
export type GraphFacts = { entities: EntityFact[]; aliases: AliasFact[]; edges: EdgeFact[]; existing?: EntityRef[] };

export const refKey = (r: EntityRef) => `${r.type}|${r.key}`;

// Long URLs would exceed the btree row limit on the unique index; hash them instead.
const MAX_KEY = 512;

/** The canonical key for a value of a given type. Same input, same key, whichever record it came from. */
export function canonicalKey(type: EntityType, raw: string): string {
  let v = raw.trim();
  if (type === "device") v = v.toLowerCase().split(".")[0]!;
  else if (type !== "url" && type !== "indicator" && type !== "alert") v = v.toLowerCase();
  return v.length > MAX_KEY ? `sha256:${createHash("sha256").update(v).digest("hex")}` : v;
}

/** Names an account may appear under: as given, without a DOMAIN\ prefix, and without an @domain suffix. */
export function accountCandidates(name: string): string[] {
  const v = canonicalKey("user", name);
  const out = new Set([v]);
  if (v.includes("\\")) out.add(v.split("\\").pop()!);
  if (v.includes("@")) out.add(v.split("@")[0]!);
  return [...out].filter(Boolean);
}

const OBSERVABLE_ENTITY: Record<Observable["type"], EntityType | null> = {
  ipv4: "ip", ipv6: "ip", domain: "domain", url: "url", md5: "file", sha1: "file", sha256: "file", email: "email", hostname: "device", user: "user", cve: null,
};

/** The entity an observable names, or null for types the graph does not model (CVEs). */
export function observableEntity(o: Pick<Observable, "type" | "value">): (EntityRef & { displayName: string; identifiers: Record<string, unknown> }) | null {
  const type = OBSERVABLE_ENTITY[o.type];
  if (!type) return null;
  if (type === "file") return { type, key: canonicalKey(type, `${o.type}:${o.value}`), displayName: o.value, identifiers: { [o.type]: o.value.toLowerCase() } };
  const key = canonicalKey(type, o.value);
  return { type, key, displayName: type === "device" ? key : o.value, identifiers: type === "device" ? { hostname: o.value } : {} };
}

const ASSET_ENTITY: Record<string, EntityType> = {
  endpoint: "device", server: "device", network_device: "device", identity: "identity", cloud_resource: "cloud_resource", application: "cloud_resource", saas: "cloud_resource", domain: "domain", ip: "ip",
};

export type AssetInput = { id: string; kind: string; name: string; hostname: string | null; ips?: string[]; os?: string | null; dedupeKeys?: string[]; firstSeen?: Date; lastSeen?: Date };

/** The entity for an inventory asset. Devices key on short hostname, the same key asset dedup uses. */
export function assetRef(a: Pick<AssetInput, "id" | "kind" | "name" | "hostname">): EntityRef {
  const type = ASSET_ENTITY[a.kind] ?? "device";
  if (type === "identity" || type === "domain" || type === "ip") return { type, key: canonicalKey(type, a.name) };
  if (a.hostname) return { type, key: canonicalKey("device", a.hostname) };
  return { type, key: `asset:${a.id}` };
}

/** Inventory → entity, aliases, device → IP edges and, when given, user → identity name matches. */
export function assetFacts(a: AssetInput, source: string, opts: { matchingUsers?: string[] } = {}): GraphFacts {
  const ref = assetRef(a);
  const seenAt = a.lastSeen ?? new Date();
  const evidence: Evidence = { type: "asset", id: a.id };
  const facts: GraphFacts = {
    entities: [{ ...ref, displayName: a.name, identifiers: { assetId: a.id, kind: a.kind, ...(a.hostname ? { hostname: a.hostname } : {}), ...(a.os ? { os: a.os } : {}) }, source, seenAt, firstSeen: a.firstSeen }],
    aliases: [{ entity: ref, kind: "asset_id", value: a.id, source }],
    edges: [],
    existing: [],
  };
  for (const k of a.dedupeKeys ?? []) {
    const i = k.indexOf(":");
    if (i > 0) facts.aliases.push({ entity: ref, kind: k.slice(0, i), value: k.slice(i + 1), source });
  }
  if (a.hostname?.includes(".")) facts.aliases.push({ entity: ref, kind: "fqdn", value: a.hostname.toLowerCase(), source });
  if (ref.type === "identity") {
    for (const acct of accountCandidates(a.name)) facts.aliases.push({ entity: ref, kind: "account", value: acct, source });
    for (const u of opts.matchingUsers ?? []) {
      const user: EntityRef = { type: "user", key: u };
      facts.existing!.push(user);
      facts.edges.push({ from: user, to: ref, type: "same_as", provenance: "inferred", evidence, seenAt });
    }
  }
  if (ref.type === "device" || ref.type === "cloud_resource") {
    for (const ip of a.ips ?? []) {
      const ipRef: EntityRef = { type: "ip", key: canonicalKey("ip", ip) };
      facts.entities.push({ ...ipRef, displayName: ip, source, seenAt });
      facts.edges.push({ from: ref, to: ipRef, type: "has_ip", provenance: "observed", evidence, seenAt });
    }
  }
  return facts;
}

export type AlertGraphInput = {
  alert: {
    id: string;
    title: string;
    source: string;
    externalId: string;
    severity: string;
    category: string | null;
    occurredAt: Date;
    userName: string | null;
    raw?: unknown;
    ocsfSourceEvent?: NetworkActivity | Authentication | null;
  };
  /** The asset the alert resolved to, if any. */
  asset: Pick<AssetInput, "id" | "kind" | "name" | "hostname"> | null;
  /** Hostname the alert reported, used when no asset matched. */
  hostname: string | null;
  observables: Pick<Observable, "type" | "value">[];
  /** Stored intel_matches rows for the alert. */
  intel: { id: string; match: IntelMatch }[];
  /** The identity entity the alert's user name resolved to, if any (see accountCandidates). */
  identity?: { key: string } | null;
};

/** Did the alert record a sign-in, and did it succeed? Null when the alert is not about authentication. */
export function loginOutcome(a: AlertGraphInput["alert"]): "success" | "failure" | null {
  const ev = a.ocsfSourceEvent;
  if (ev?.class_uid === 3002) return ev.status_id === 2 ? "failure" : "success";
  const groups = ((a.raw as { rule?: { groups?: unknown } } | undefined)?.rule?.groups ?? []) as unknown[];
  if (groups.some((g) => typeof g === "string" && /authentication_fail/.test(g))) return "failure";
  if (groups.some((g) => typeof g === "string" && /authentication_success/.test(g))) return "success";
  const t = a.title.toLowerCase();
  if (!/log ?on|log ?in|sign-?in|signed in/.test(t)) return null;
  return /fail|invalid|denied|bad password/.test(t) ? "failure" : /success|logged on|signed in/.test(t) ? "success" : null;
}

/**
 * Facts one alert asserts. Every edge cites the alert (or the intel match) as evidence.
 * logged_into is observed when the alert is a successful sign-in, inferred when the user merely
 * acted on the device, and omitted for failed sign-ins: a failed logon is not a session.
 */
export function alertFacts(input: AlertGraphInput): GraphFacts {
  const { alert: a } = input;
  const seenAt = a.occurredAt;
  const source = a.source;
  const evidence: Evidence = { type: "alert", id: a.id };
  const facts: GraphFacts = { entities: [], aliases: [], edges: [], existing: [] };
  const alertRef: EntityRef = { type: "alert", key: a.id };
  facts.entities.push({ ...alertRef, displayName: a.title, identifiers: { alertId: a.id, source: a.source, externalId: a.externalId, severity: a.severity, ...(a.category ? { category: a.category } : {}) }, source, seenAt });

  const seen = new Set<string>([refKey(alertRef)]);
  const alertedOn = (ref: EntityRef) => {
    if (seen.has(refKey(ref))) return;
    seen.add(refKey(ref));
    facts.edges.push({ from: alertRef, to: ref, type: "alerted_on", provenance: "observed", evidence, seenAt });
  };

  let device: EntityRef | null = null;
  if (input.asset) {
    device = assetRef(input.asset);
    facts.entities.push({ ...device, displayName: input.asset.name, identifiers: { assetId: input.asset.id, ...(input.asset.hostname ? { hostname: input.asset.hostname } : {}) }, source, seenAt });
    facts.aliases.push({ entity: device, kind: "asset_id", value: input.asset.id, source });
  } else if (input.hostname) {
    device = { type: "device", key: canonicalKey("device", input.hostname) };
    facts.entities.push({ ...device, displayName: device.key, identifiers: { hostname: input.hostname }, source, seenAt });
  }
  if (device) {
    if (input.hostname?.includes(".")) facts.aliases.push({ entity: device, kind: "fqdn", value: input.hostname.toLowerCase(), source });
    alertedOn(device);
  }

  let user: EntityRef | null = null;
  if (a.userName?.trim()) {
    user = { type: "user", key: canonicalKey("user", a.userName) };
    facts.entities.push({ ...user, displayName: a.userName.trim(), source, seenAt });
    alertedOn(user);
    if (device && device.type === "device") {
      const outcome = loginOutcome(a);
      if (outcome !== "failure") facts.edges.push({ from: user, to: device, type: "logged_into", provenance: outcome === "success" ? "observed" : "inferred", evidence, seenAt });
    }
    if (input.identity) {
      const identity: EntityRef = { type: "identity", key: input.identity.key };
      facts.existing!.push(identity);
      facts.edges.push({ from: user, to: identity, type: "same_as", provenance: "inferred", evidence, seenAt });
    }
  }

  const observableRefs = new Map<string, EntityRef>();
  for (const o of input.observables) {
    const e = observableEntity(o);
    if (!e) continue;
    // The alert's own host and user are already linked above under their canonical refs.
    if (e.type === "device" && device?.type === "device" && e.key === device.key) continue;
    if (e.type === "user" && user && e.key === user.key) continue;
    facts.entities.push({ type: e.type, key: e.key, displayName: e.displayName, identifiers: e.identifiers, source, seenAt });
    observableRefs.set(`${o.type}|${o.value.toLowerCase()}`, e);
    alertedOn(e);
  }

  const ev = a.ocsfSourceEvent;
  if (ev?.class_uid === 4001 && ev.src_endpoint?.ip && ev.dst_endpoint?.ip) {
    const src: EntityRef = { type: "ip", key: canonicalKey("ip", ev.src_endpoint.ip) };
    const dst: EntityRef = { type: "ip", key: canonicalKey("ip", ev.dst_endpoint.ip) };
    if (src.key !== dst.key) {
      facts.entities.push({ ...src, displayName: ev.src_endpoint.ip, source, seenAt }, { ...dst, displayName: ev.dst_endpoint.ip, source, seenAt });
      facts.edges.push({ from: src, to: dst, type: "communicated_with", provenance: "observed", evidence, seenAt });
    }
  }

  for (const { id, match: m } of input.intel) {
    const intelEvidence: Evidence = { type: "intel_match", id };
    const indicator: EntityRef = { type: "indicator", key: canonicalKey("indicator", m.openctiId) };
    facts.entities.push({
      ...indicator,
      displayName: `${m.observable.value} (${m.entityType})`,
      identifiers: { openctiId: m.openctiId, entityType: m.entityType, verdict: m.verdict, ...(m.score !== null ? { score: m.score } : {}), ...(m.source ? { source: m.source } : {}) },
      source: "opencti",
      seenAt,
    });
    facts.edges.push({ from: alertRef, to: indicator, type: "matched", provenance: "observed", evidence: intelEvidence, seenAt });
    let target = observableRefs.get(`${m.observable.type}|${m.observable.value.toLowerCase()}`);
    if (!target) {
      const e = observableEntity(m.observable as Pick<Observable, "type" | "value">);
      if (e) facts.entities.push({ type: e.type, key: e.key, displayName: e.displayName, identifiers: e.identifiers, source, seenAt });
      target = e ?? undefined;
    }
    if (target) facts.edges.push({ from: indicator, to: { type: target.type, key: target.key }, type: "indicates", provenance: "observed", evidence: intelEvidence, seenAt });
    const attributed: [EntityType, string][] = [
      ...[...m.threatActors, ...m.intrusionSets].map((n): [EntityType, string] => ["threat_actor", n]),
      ...m.campaigns.map((n): [EntityType, string] => ["campaign", n]),
    ];
    for (const [type, name] of attributed) {
      if (!name.trim()) continue;
      const ref: EntityRef = { type, key: canonicalKey(type, name) };
      facts.entities.push({ ...ref, displayName: name.trim(), source: "opencti", seenAt });
      facts.edges.push({ from: indicator, to: ref, type: "attributed_to", provenance: "observed", evidence: intelEvidence, seenAt });
    }
  }
  return facts;
}
