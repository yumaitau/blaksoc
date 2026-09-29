import { integer, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import type { AssessmentResult } from "@/lib/essential-eight/score";
import { tenants } from "./platform";

export const e8Assessments = pgTable("e8_assessments", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  assessedAt: timestamp("assessed_at", { withTimezone: true }).notNull(),
  cadenceDays: integer("cadence_days").notNull(),
  nextDue: timestamp("next_due", { withTimezone: true }).notNull(),
  owner: text("owner").notNull(),
  answers: jsonb("answers").$type<Record<string, "yes" | "no">>().notNull(),
  result: jsonb("result").$type<AssessmentResult>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const e8Tasks = pgTable("e8_tasks", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  assessmentId: uuid("assessment_id").notNull().references(() => e8Assessments.id, { onDelete: "cascade" }),
  requirementId: text("requirement_id").notNull(),
  strategy: text("strategy").notNull(),
  title: text("title").notNull(),
  owner: text("owner").notNull(),
  dueAt: timestamp("due_at", { withTimezone: true }).notNull(),
  priority: integer("priority").notNull(),
  status: text("status").notNull().default("open"),
});
