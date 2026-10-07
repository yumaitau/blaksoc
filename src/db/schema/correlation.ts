import { boolean, index, integer, jsonb, pgTable, primaryKey, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import type { ClauseMatch } from "@/lib/correlation/engine";
import { tenants } from "./platform";
import { alerts, incidents } from "./security";

/** One row per correlated alert: the rule version that fired and exactly which events met which clause. */
export const correlationFindings = pgTable(
  "correlation_findings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    ruleId: text("rule_id").notNull(),
    ruleVersion: integer("rule_version").notNull(),
    /** Rule + entity + anchor event. Unique per tenant so a re-run never raises the same finding twice. */
    dedupeKey: text("dedupe_key").notNull(),
    entity: jsonb("entity").$type<Record<string, string>>().notNull(),
    alertId: uuid("alert_id").references(() => alerts.id, { onDelete: "set null" }),
    firstAt: timestamp("first_at", { withTimezone: true }).notNull(),
    lastAt: timestamp("last_at", { withTimezone: true }).notNull(),
    matches: jsonb("matches").$type<ClauseMatch[]>().notNull(),
    explanation: text("explanation").array().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("correlation_findings_dedupe").on(t.tenantId, t.dedupeKey), index("correlation_findings_tenant").on(t.tenantId, t.createdAt)],
);

/** Per-tenant override of a built-in rule's enabledByDefault. */
export const correlationRuleSettings = pgTable(
  "correlation_rule_settings",
  {
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    ruleId: text("rule_id").notNull(),
    enabled: boolean("enabled").notNull(),
    updatedBy: text("updated_by"),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.tenantId, t.ruleId] })],
);

/** How far the scheduled evaluation has got for a tenant. The next run looks back one rule window from here. */
export const correlationCursors = pgTable("correlation_cursors", {
  tenantId: uuid("tenant_id").primaryKey().references(() => tenants.id, { onDelete: "cascade" }),
  evaluatedThrough: timestamp("evaluated_through", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Alerts an analyst ungrouped. Automatic grouping leaves them alone from then on. */
export const incidentGroupExclusions = pgTable("incident_group_exclusions", {
  alertId: uuid("alert_id").primaryKey().references(() => alerts.id, { onDelete: "cascade" }),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").references(() => incidents.id, { onDelete: "set null" }),
  actorId: text("actor_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
