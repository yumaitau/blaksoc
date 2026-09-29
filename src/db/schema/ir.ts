import { index, integer, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

/** One saved incident-response plan. A later save keeps the earlier version. */
export const irPlans = pgTable(
  "ir_plans",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    version: integer("version").notNull(),
    culturalProtocol: text("cultural_protocol").notNull().default(""),
    bank: text("bank").notNull().default(""),
    insurer: text("insurer").notNull().default(""),
    itProvider: text("it_provider").notNull().default(""),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("ir_plans_tenant_version").on(t.tenantId, t.version)],
);

/** A finished tabletop. This row does not record an advisory-group review. */
export const irExercises = pgTable(
  "ir_exercises",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    scenarioId: text("scenario_id").notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }).notNull().defaultNow(),
    notes: text("notes").notNull().default(""),
    lessons: text("lessons").notNull().default(""),
  },
  (t) => [index("ir_exercises_tenant").on(t.tenantId, t.completedAt)],
);
