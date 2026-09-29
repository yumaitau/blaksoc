import { boolean, doublePrecision, integer, jsonb, pgTable, primaryKey, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

// Global reference data. Not tenant data, so no RLS. OpenCTI stays the CTI system
// of record; these tables hold only what blakSOC needs locally for scoring and UI.

/** CVE scoring context (NVD / FIRST EPSS / CISA KEV), refreshed by the worker. */
export const cveIntel = pgTable("cve_intel", {
  cve: text("cve").primaryKey(),
  summary: text("summary"),
  cvss: doublePrecision("cvss"),
  epss: doublePrecision("epss"),
  epssPercentile: doublePrecision("epss_percentile"),
  kev: boolean("kev").notNull().default(false),
  kevDateAdded: text("kev_date_added"),
  kevDueDate: text("kev_due_date"),
  kevRansomware: boolean("kev_ransomware").notNull().default(false),
  /** Count of OpenCTI threat entities (actors/malware/campaigns) related to the CVE. */
  openctiThreats: integer("opencti_threats").notNull().default(0),
  openctiRefs: jsonb("opencti_refs").$type<{ id: string; name: string; type: string }[]>().notNull().default([]),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const attackTechniques = pgTable("attack_techniques", {
  id: text("id").primaryKey(), // T1059.001
  name: text("name").notNull(),
  tactics: text("tactics").array().notNull(),
  parentId: text("parent_id"),
  description: text("description"),
});

/** Catalogue of intel feeds wired into OpenCTI, with licensing constraints. */
export const intelFeeds = pgTable("intel_feeds", {
  key: text("key").primaryKey(),
  name: text("name").notNull(),
  category: text("category").notNull(),
  license: text("license").notNull(),
  commercial: boolean("commercial").notNull().default(false),
  enabled: boolean("enabled").notNull().default(true),
  /** OpenCTI connector image / identity name used to attribute objects to this feed. */
  connector: jsonb("connector").$type<{ image?: string; createdBy?: string; url?: string }>().notNull().default({}),
  notes: text("notes"),
});

/** Per-tenant entitlement to feeds. Commercial feeds require an explicit row. */
export const tenantFeedEntitlements = pgTable(
  "tenant_feed_entitlements",
  {
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    feedKey: text("feed_key").notNull().references(() => intelFeeds.key, { onDelete: "cascade" }),
    allowed: boolean("allowed").notNull().default(true),
  },
  (t) => [primaryKey({ columns: [t.tenantId, t.feedKey] })],
);

/** Public advisories (ACSC / CISA / CERTs) ingested for the Australian intel view. */
export const advisories = pgTable("advisories", {
  id: uuid("id").primaryKey().defaultRandom(),
  source: text("source").notNull(),
  externalId: text("external_id").notNull().unique(),
  title: text("title").notNull(),
  url: text("url").notNull(),
  summary: text("summary"),
  publishedAt: timestamp("published_at", { withTimezone: true }),
  cves: text("cves").array().notNull().default([]),
  tags: text("tags").array().notNull().default([]),
  attackTechniques: text("attack_techniques").array().notNull().default([]),
  openctiReportId: text("opencti_report_id"),
  ingestedAt: timestamp("ingested_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Analyst sector tags on OpenCTI objects, mirrored to OpenCTI labels. */
export const intelTags = pgTable("intel_tags", {
  openctiId: text("opencti_id").primaryKey(),
  entityType: text("entity_type").notNull(),
  name: text("name").notNull(),
  tags: text("tags").array().notNull(),
  updatedBy: text("updated_by"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});
