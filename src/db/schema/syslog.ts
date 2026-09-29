import { index, integer, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

/** Per-tenant token that a firewall, or Vector in front of it, uses to deliver syslog. */
export const syslogSources = pgTable("syslog_sources", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  tokenHash: text("token_hash").notNull().unique(),
  allowIps: text("allow_ips").array().notNull().default([]),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Hot lines. Cold lines stay here with tier = cold after the archive copy. */
export const syslogEvents = pgTable(
  "syslog_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    sourceId: uuid("source_id").notNull().references(() => syslogSources.id, { onDelete: "cascade" }),
    vendor: text("vendor").notNull(),
    action: text("action").notNull(),
    line: text("line").notNull(),
    byteLen: integer("byte_len").notNull(),
    tier: text("tier").notNull().default("hot"),
    ingestedAt: timestamp("ingested_at", { withTimezone: true }).notNull().defaultNow(),
    retainUntil: timestamp("retain_until", { withTimezone: true }).notNull(),
  },
  (t) => [index("syslog_events_tenant_hot").on(t.tenantId, t.tier, t.ingestedAt)],
);

/** Cold index. Region is an Australian AWS region. Search and restore read the object store; body is the copy taken at archive time. */
export const syslogArchive = pgTable("syslog_archive", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  eventId: uuid("event_id").notNull().unique(),
  region: text("region").notNull(),
  objectKey: text("object_key").notNull(),
  body: text("body").notNull(),
  archivedAt: timestamp("archived_at", { withTimezone: true }).notNull().defaultNow(),
});
