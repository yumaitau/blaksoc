import { boolean, index, integer, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { integrations } from "./security";
import { severity } from "./security";
import { tenants } from "./platform";

/** Sigma rule head. tenantId null = global rule maintained by Yuma IT. */
export const sigmaRules = pgTable(
  "sigma_rules",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
    sigmaId: text("sigma_id").notNull(),
    title: text("title").notNull(),
    description: text("description"),
    status: text("status").notNull().default("experimental"),
    severity: severity("severity").notNull().default("medium"),
    confidence: integer("confidence").notNull().default(50),
    logsource: jsonb("logsource").$type<Record<string, string>>().notNull().default({}),
    attackTechniques: text("attack_techniques").array().notNull().default([]),
    falsePositives: text("false_positives").array().notNull().default([]),
    currentVersion: integer("current_version").notNull().default(1),
    enabled: boolean("enabled").notNull().default(true),
    createdBy: text("created_by"),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("sigma_rules_tenant").on(t.tenantId)],
);

export const sigmaRuleVersions = pgTable(
  "sigma_rule_versions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    ruleId: uuid("rule_id").notNull().references(() => sigmaRules.id, { onDelete: "cascade" }),
    tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
    version: integer("version").notNull(),
    yaml: text("yaml").notNull(),
    sha256: text("sha256").notNull(),
    changeNote: text("change_note"),
    createdBy: text("created_by"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("sigma_rule_versions_unique").on(t.ruleId, t.version)],
);

export const sigmaRuleTests = pgTable("sigma_rule_tests", {
  id: uuid("id").primaryKey().defaultRandom(),
  ruleId: uuid("rule_id").notNull().references(() => sigmaRules.id, { onDelete: "cascade" }),
  tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
  version: integer("version").notNull(),
  cases: jsonb("cases").$type<{ name: string; event: Record<string, unknown>; expect: boolean }[]>().notNull(),
  results: jsonb("results").$type<{ name: string; matched: boolean; pass: boolean }[]>().notNull(),
  passed: boolean("passed").notNull(),
  ranBy: text("ran_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/** A rule version deployed as a scheduled query against a SIEM for one tenant. */
export const detectionDeployments = pgTable(
  "detection_deployments",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    ruleId: uuid("rule_id").notNull().references(() => sigmaRules.id, { onDelete: "cascade" }),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    integrationId: uuid("integration_id").references(() => integrations.id, { onDelete: "set null" }),
    version: integer("version").notNull(),
    query: text("query").notNull(),
    status: text("status").notNull().default("active"),
    deployedBy: text("deployed_by"),
    deployedAt: timestamp("deployed_at", { withTimezone: true }).notNull().defaultNow(),
    lastRunAt: timestamp("last_run_at", { withTimezone: true }),
    lastHitCount: integer("last_hit_count"),
  },
  (t) => [uniqueIndex("detection_deployments_unique").on(t.ruleId, t.tenantId)],
);
