import {
  bigserial, boolean, doublePrecision, index, integer, jsonb, pgEnum, pgTable, primaryKey, text, timestamp, uniqueIndex, uuid,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import type { GroupReason } from "@/lib/correlation/grouping";
import type { Authentication, DetectionFinding, NetworkActivity } from "@/lib/ocsf/schema";
import { user } from "./auth";
import { sites, tenants } from "./platform";

export const severity = pgEnum("severity", ["informational", "low", "medium", "high", "critical"]);
export const alertStatus = pgEnum("alert_status", [
  "NEW", "TRIAGING", "INVESTIGATING", "ESCALATED", "CONTAINED", "RESOLVED", "FALSE_POSITIVE",
]);
export const incidentStatus = pgEnum("incident_status", [
  "OPEN", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED",
]);
export const assetKind = pgEnum("asset_kind", [
  "endpoint", "server", "identity", "cloud_resource", "application", "domain", "ip", "network_device", "saas",
]);
export const observableType = pgEnum("observable_type", [
  "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "hostname", "cve", "user",
]);

export type RiskFactor = {
  key: string;
  label: string;
  /** Points contributed to the 0–100 score. */
  points: number;
  /** Human-readable evidence for the factor. */
  evidence: string;
  /** Link to the record backing the evidence, where one exists. */
  ref?: { type: string; id: string };
};

export type IntelContext = {
  verdict: "malicious" | "suspicious" | "unknown" | "benign";
  matches: IntelMatch[];
  checkedAt: string;
};

export type IntelMatch = {
  observable: { type: string; value: string };
  openctiId: string;
  entityType: string;
  verdict: "malicious" | "suspicious" | "unknown" | "benign";
  score: number | null;
  confidence: number | null;
  source: string | null;
  markings: string[];
  labels: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  threatActors: string[];
  intrusionSets: string[];
  malware: string[];
  campaigns: string[];
  attackPatterns: { id: string | null; name: string }[];
  relatedIndicators: { id: string; name: string; pattern: string | null }[];
  sightings: number;
};

export const integrations = pgTable("integrations", {
  id: uuid("id").primaryKey().defaultRandom(),
  /** Null = platform-owned (e.g. shared Wazuh cluster, OpenCTI). */
  tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
  category: text("category").notNull(),
  provider: text("provider").notNull(),
  name: text("name").notNull(),
  config: jsonb("config").$type<Record<string, unknown>>().notNull().default({}),
  /** AES-256-GCM ciphertext. Never selected into client payloads. */
  secretCiphertext: text("secret_ciphertext"),
  enabled: boolean("enabled").notNull().default(true),
  /** Set when a downgrade disabled the row. Upgrade resumes these and leaves admin-disabled rows alone. */
  pausedByPlan: boolean("paused_by_plan").notNull().default(false),
  status: text("status").notNull().default("unknown"),
  permissions: text("permissions").array().notNull().default([]),
  lastSuccessAt: timestamp("last_success_at", { withTimezone: true }),
  lastError: text("last_error"),
  lastErrorAt: timestamp("last_error_at", { withTimezone: true }),
  health: jsonb("health").$type<Record<string, unknown>>(),
  /** Alert poll position. Durable so a Redis loss neither replays nor skips a provider window. */
  pollCursor: text("poll_cursor"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Which tenants a shared integration serves, and how to select their data (e.g. Wazuh agent groups). */
export const integrationTenantLinks = pgTable(
  "integration_tenant_links",
  {
    integrationId: uuid("integration_id").notNull().references(() => integrations.id, { onDelete: "cascade" }),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    selector: jsonb("selector").$type<{ agentGroups?: string[]; agentIds?: string[] }>().notNull().default({}),
  },
  (t) => [primaryKey({ columns: [t.integrationId, t.tenantId] })],
);

export const assets = pgTable(
  "assets",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    siteId: uuid("site_id").references(() => sites.id, { onDelete: "set null" }),
    kind: assetKind("kind").notNull(),
    name: text("name").notNull(),
    hostname: text("hostname"),
    ips: text("ips").array().notNull().default([]),
    os: text("os"),
    owner: text("owner"),
    /** 1 (low) – 5 (crown jewel). */
    criticality: integer("criticality").notNull().default(3),
    exposure: text("exposure").notNull().default("internal"),
    /** Identity assets: privilege tier. */
    privileged: boolean("privileged").notNull().default(false),
    tags: text("tags").array().notNull().default([]),
    software: jsonb("software").$type<{ name: string; version: string }[]>().notNull().default([]),
    attributes: jsonb("attributes").$type<Record<string, unknown>>().notNull().default({}),
    /** Normalised identity keys used for cross-integration deduplication. */
    dedupeKeys: text("dedupe_keys").array().notNull().default([]),
    agentStatus: text("agent_status"),
    riskScore: integer("risk_score").notNull().default(0),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("assets_tenant").on(t.tenantId), index("assets_dedupe").using("gin", t.dedupeKeys)],
);

export const assetSources = pgTable(
  "asset_sources",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    assetId: uuid("asset_id").notNull().references(() => assets.id, { onDelete: "cascade" }),
    integrationId: uuid("integration_id").notNull().references(() => integrations.id, { onDelete: "cascade" }),
    externalId: text("external_id").notNull(),
    raw: jsonb("raw"),
    lastSyncedAt: timestamp("last_synced_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("asset_sources_ext").on(t.integrationId, t.externalId)],
);

export const incidents = pgTable(
  "incidents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    ref: bigserial("ref", { mode: "number" }).notNull(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    description: text("description"),
    severity: severity("severity").notNull(),
    status: incidentStatus("status").notNull().default("OPEN"),
    ownerId: text("owner_id").references(() => user.id),
    collaboratorIds: text("collaborator_ids").array().notNull().default([]),
    attackTechniques: text("attack_techniques").array().notNull().default([]),
    riskScore: integer("risk_score").notNull().default(0),
    containment: text("containment"),
    remediation: text("remediation"),
    rootCause: text("root_cause"),
    lessonsLearned: text("lessons_learned"),
    slaDueAt: timestamp("sla_due_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    containedAt: timestamp("contained_at", { withTimezone: true }),
    closedAt: timestamp("closed_at", { withTimezone: true }),
    /** Set on incidents automatic grouping opened (`grp:` + earliest alert id). Null otherwise. */
    groupingKey: text("grouping_key"),
  },
  (t) => [
    index("incidents_tenant_status").on(t.tenantId, t.status),
    uniqueIndex("incidents_grouping_key").on(t.tenantId, t.groupingKey).where(sql`${t.groupingKey} is not null`),
  ],
);

export const alerts = pgTable(
  "alerts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    integrationId: uuid("integration_id").references(() => integrations.id, { onDelete: "set null" }),
    source: text("source").notNull(),
    externalId: text("external_id").notNull(),
    ruleId: text("rule_id"),
    title: text("title").notNull(),
    description: text("description"),
    category: text("category"),
    /** Raw SIEM severity as reported (e.g. Wazuh level 0–15). */
    siemSeverity: integer("siem_severity"),
    severity: severity("severity").notNull(),
    riskScore: integer("risk_score").notNull().default(0),
    riskFactors: jsonb("risk_factors").$type<RiskFactor[]>().notNull().default([]),
    status: alertStatus("status").notNull().default("NEW"),
    assigneeId: text("assignee_id").references(() => user.id),
    assetId: uuid("asset_id").references(() => assets.id, { onDelete: "set null" }),
    userName: text("user_name"),
    attackTechniques: text("attack_techniques").array().notNull().default([]),
    intel: jsonb("intel").$type<IntelContext>(),
    intelVerdict: text("intel_verdict").notNull().default("unchecked"),
    incidentId: uuid("incident_id").references(() => incidents.id, { onDelete: "set null" }),
    raw: jsonb("raw"),
    /** The alert as an OCSF Detection Finding (2004). See src/lib/ocsf. */
    ocsf: jsonb("ocsf").$type<DetectionFinding>(),
    /** The source record in its OCSF activity class, when blakSOC maps one (syslog → 4001, Entra sign-in → 3002). */
    ocsfSourceEvent: jsonb("ocsf_source_event").$type<NetworkActivity | Authentication>(),
    /** Mapper version that wrote `ocsf` (NORMALIZATION_VERSION). Null when no OCSF record was written. */
    normalizationVersion: text("normalization_version"),
    occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull(),
    ingestedAt: timestamp("ingested_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("alerts_source_ext").on(t.tenantId, t.source, t.externalId),
    index("alerts_queue").on(t.tenantId, t.status, t.riskScore),
    index("alerts_occurred").on(t.occurredAt),
    index("alerts_tenant_occurred").on(t.tenantId, t.occurredAt),
  ],
);

export const observables = pgTable(
  "observables",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    type: observableType("type").notNull(),
    value: text("value").notNull(),
    verdict: text("verdict").notNull().default("unchecked"),
    sightings: integer("sightings").notNull().default(0),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("observables_unique").on(t.tenantId, t.type, t.value)],
);

export const alertObservables = pgTable(
  "alert_observables",
  {
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    alertId: uuid("alert_id").notNull().references(() => alerts.id, { onDelete: "cascade" }),
    observableId: uuid("observable_id").notNull().references(() => observables.id, { onDelete: "cascade" }),
    field: text("field"),
  },
  (t) => [primaryKey({ columns: [t.alertId, t.observableId] })],
);

/** Confirmed intel hits in a tenant, feeding dashboards and the sightings feedback loop. */
export const intelMatches = pgTable(
  "intel_matches",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    alertId: uuid("alert_id").references(() => alerts.id, { onDelete: "cascade" }),
    observableId: uuid("observable_id").references(() => observables.id, { onDelete: "cascade" }),
    openctiId: text("opencti_id").notNull(),
    verdict: text("verdict").notNull(),
    score: integer("score"),
    summary: jsonb("summary").$type<IntelMatch>().notNull(),
    sightingStatus: text("sighting_status").notNull().default("not_shared"),
    sightingId: text("sighting_id"),
    matchedAt: timestamp("matched_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("intel_matches_tenant").on(t.tenantId, t.matchedAt)],
);

export const incidentAlerts = pgTable(
  "incident_alerts",
  {
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
    alertId: uuid("alert_id").notNull().references(() => alerts.id, { onDelete: "cascade" }),
    /** `manual` (analyst or playbook) or `auto` (automatic grouping, which an analyst can undo). */
    origin: text("origin").notNull().default("manual"),
    /** Why automatic grouping linked the alert. */
    reason: jsonb("reason").$type<GroupReason>(),
    /** Alert status before grouping escalated it; restored on ungroup. */
    priorStatus: alertStatus("prior_status"),
    linkedAt: timestamp("linked_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.incidentId, t.alertId] })],
);

/** Affected assets, identities, observables and intel objects on an incident. */
export const incidentLinks = pgTable(
  "incident_links",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(), // asset | identity | observable | intel
    refId: text("ref_id").notNull(),
    label: text("label").notNull(),
    data: jsonb("data"),
  },
  (t) => [uniqueIndex("incident_links_unique").on(t.incidentId, t.kind, t.refId)],
);

export const incidentTimeline = pgTable(
  "incident_timeline",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
    occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull(),
    origin: text("origin").notNull(), // machine | analyst | ai | customer
    category: text("category").notNull(), // detection | intel | response | analyst | status | grouping
    title: text("title").notNull(),
    detail: text("detail"),
    actorId: text("actor_id"),
    refType: text("ref_type"),
    refId: text("ref_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("incident_timeline_incident").on(t.incidentId, t.occurredAt)],
);

export const incidentNotes = pgTable("incident_notes", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  authorId: text("author_id").references(() => user.id),
  body: text("body").notNull(),
  /** internal = SOC only; customer = visible in portal. */
  visibility: text("visibility").notNull().default("internal"),
  aiGenerated: boolean("ai_generated").notNull().default(false),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const incidentTasks = pgTable("incident_tasks", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  title: text("title").notNull(),
  done: boolean("done").notNull().default(false),
  assigneeId: text("assignee_id").references(() => user.id),
  dueAt: timestamp("due_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  /** Set once a playbook task is forwarded to the Kelpie case as a comment. */
  kelpieCommentId: text("kelpie_comment_id"),
});

export const evidence = pgTable("evidence", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  kind: text("kind").notNull(),
  sha256: text("sha256"),
  storageUri: text("storage_uri"),
  description: text("description"),
  collectedBy: text("collected_by"),
  collectedAt: timestamp("collected_at", { withTimezone: true }).notNull().defaultNow(),
});

export const vulnerabilities = pgTable(
  "vulnerabilities",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    assetId: uuid("asset_id").notNull().references(() => assets.id, { onDelete: "cascade" }),
    cve: text("cve").notNull(),
    title: text("title"),
    packageName: text("package_name"),
    packageVersion: text("package_version"),
    fixedVersion: text("fixed_version"),
    cvss: doublePrecision("cvss"),
    source: text("source").notNull().default("wazuh"),
    status: text("status").notNull().default("open"),
    priorityScore: integer("priority_score").notNull().default(0),
    priorityFactors: jsonb("priority_factors").$type<RiskFactor[]>().notNull().default([]),
    evidence: jsonb("evidence").$type<{ request: string; response: string } | null>(),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("vulns_unique").on(t.tenantId, t.assetId, t.cve, t.packageName),
    index("vulns_priority").on(t.tenantId, t.status, t.priorityScore),
  ],
);
