import { boolean, index, integer, jsonb, pgEnum, pgTable, text, timestamp, uniqueIndex, uuid, type AnyPgColumn } from "drizzle-orm/pg-core";
import { user } from "./auth";

export const tenantKind = pgEnum("tenant_kind", ["mssp", "partner", "customer"]);
export const deploymentMode = pgEnum("deployment_mode", ["shared", "dedicated"]);

/** Intel sector tags usable against tenants and intelligence. */
export const SECTOR_TAGS = [
  "AUSTRALIA",
  "GOVERNMENT",
  "INDIGENOUS_BUSINESS",
  "HEALTHCARE",
  "CRITICAL_INFRASTRUCTURE",
  "SMB",
  "FINANCE",
  "EDUCATION",
] as const;
export type SectorTag = (typeof SECTOR_TAGS)[number];

export type SharingPolicy = {
  /** Create OpenCTI sightings for confirmed detections. */
  createSightings: boolean;
  /** "anonymised" attributes sightings to a sector identity, never the customer. */
  attribution: "anonymised" | "named" | "none";
  /** TLP ceiling for anything leaving the tenant. */
  maxTlp: "TLP:CLEAR" | "TLP:GREEN" | "TLP:AMBER" | "TLP:AMBER+STRICT" | "TLP:RED";
};

export type AiPolicy = {
  enabled: boolean;
  /** Provider ids permitted for this tenant's data. Empty = platform default only. */
  allowedProviders: string[];
  /** May raw event payloads be sent to the model (vs normalised fields only). */
  allowRawEvents: boolean;
  redactPii: boolean;
};

/** Optional telemetry limits. Absent fields use the code defaults. */
export type HealthPolicy = {
  silentHours?: number;
  pollLagMinutes?: number;
  dmarcStaleHours?: number;
  sigmaStaleHours?: number;
};

export type TenantSettings = {
  sharing: SharingPolicy;
  ai: AiPolicy;
  /** Admin opt-in: playbooks may run destructive containment without a human gate. */
  autoContainment: boolean;
  slaMinutes: { critical: number; high: number; medium: number; low: number };
  health?: HealthPolicy;
  /** Synthetic training tenant. Real integrations cannot be attached. */
  training?: boolean;
};

export const DEFAULT_TENANT_SETTINGS: TenantSettings = {
  sharing: { createSightings: false, attribution: "anonymised", maxTlp: "TLP:AMBER" },
  ai: { enabled: true, allowedProviders: [], allowRawEvents: false, redactPii: true },
  autoContainment: false,
  slaMinutes: { critical: 15, high: 60, medium: 240, low: 1440 },
};

export const tenants = pgTable("tenants", {
  id: uuid("id").primaryKey().defaultRandom(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  kind: tenantKind("kind").notNull().default("customer"),
  /** Partner that delivers this customer. Null for platform tenants and for customers Yuma IT holds directly. */
  parentId: uuid("parent_id").references((): AnyPgColumn => tenants.id, { onDelete: "restrict" }),
  /** Name shown beside blakSOC. Co-brand only; it does not replace the SOC name. */
  brandName: text("brand_name"),
  deploymentMode: deploymentMode("deployment_mode").notNull().default("shared"),
  sectors: text("sectors").array().notNull().default([]),
  status: text("status").notNull().default("active"),
  settings: jsonb("settings").$type<TenantSettings>().notNull().default(DEFAULT_TENANT_SETTINGS),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const sites = pgTable("sites", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  location: text("location"),
  timezone: text("timezone").notNull().default("Australia/Sydney"),
  /** standard or low. Low is the satellite / congested-link agent profile. */
  bandwidthProfile: text("bandwidth_profile").notNull().default("standard"),
  /** Silence override in hours. Null uses the tenant limit, then the profile default. */
  silentHours: integer("silent_hours"),
});

/** Last healthy detection coverage. A drop against this row raises one alert. */
export const healthBaselines = pgTable("health_baselines", {
  tenantId: uuid("tenant_id").primaryKey().references(() => tenants.id, { onDelete: "cascade" }),
  techniqueCount: integer("technique_count").notNull(),
  ruleCount: integer("rule_count").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const roleScope = pgEnum("role_scope", ["platform", "tenant"]);

export const roles = pgTable("roles", {
  key: text("key").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  scope: roleScope("scope").notNull(),
  permissions: text("permissions").array().notNull(),
  builtin: boolean("builtin").notNull().default(false),
});

/**
 * Grants a user a role. Platform-scope roles (tenantId null) are Yuma IT staff and
 * reach every customer tenant. Tenant-scope roles bind to one tenant. A partner role
 * on a partner tenant also reaches that partner's consented customers.
 */
export const roleAssignments = pgTable(
  "role_assignments",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: text("user_id").notNull().references(() => user.id, { onDelete: "cascade" }),
    roleKey: text("role_key").notNull().references(() => roles.key),
    tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    createdBy: text("created_by"),
  },
  (t) => [
    uniqueIndex("role_assignments_unique").on(t.userId, t.roleKey, t.tenantId),
    index("role_assignments_user").on(t.userId),
  ],
);

export const savedViews = pgTable("saved_views", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: text("user_id").references(() => user.id, { onDelete: "cascade" }),
  route: text("route").notNull(),
  name: text("name").notNull(),
  filters: jsonb("filters").$type<Record<string, string | string[]>>().notNull(),
  shared: boolean("shared").notNull().default(false),
  builtin: boolean("builtin").notNull().default(false),
  position: text("position").notNull().default("m"),
});

/** Customer agreement that a partner may open and work in the tenancy. Access ends when revokedAt is set. */
export const partnerConsents = pgTable(
  "partner_consents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    customerTenantId: uuid("customer_tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    partnerTenantId: uuid("partner_tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    consentedBy: text("consented_by").notNull(),
    consentedAt: timestamp("consented_at", { withTimezone: true }).notNull().defaultNow(),
    statement: text("statement").notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("partner_consents_pair").on(t.customerTenantId, t.partnerTenantId)],
);

/** Note for the Yuma IT SOC. Recording it does not open an external ticket. */
export const partnerEscalations = pgTable(
  "partner_escalations",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    partnerTenantId: uuid("partner_tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id"),
    note: text("note").notNull(),
    createdBy: text("created_by").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("partner_escalations_tenant").on(t.tenantId, t.createdAt)],
);
