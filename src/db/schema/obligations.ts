import { boolean, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import type { ClockKind } from "@/lib/obligations/clock";
import type { Applicability, BreachDecision, ReferralKey } from "@/lib/obligations/model";
import type { PackMark } from "@/lib/obligations/report";
import { incidents } from "./security";
import { tenants } from "./platform";

export const obligationCases = pgTable(
  "obligation_cases",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
    dueAt: timestamp("due_at", { withTimezone: true }).notNull(),
    applicability: jsonb("applicability").$type<Applicability>().notNull(),
    seriousHarm: text("serious_harm").$type<"yes" | "no" | "unsure" | null>(),
    seriousHarmRationale: text("serious_harm_rationale"),
    seriousHarmBy: text("serious_harm_by"),
    seriousHarmAt: timestamp("serious_harm_at", { withTimezone: true }),
    decision: text("decision").$type<BreachDecision | null>(),
    decisionRationale: text("decision_rationale"),
    decisionBy: text("decision_by"),
    decisionAt: timestamp("decision_at", { withTimezone: true }),
    referrals: jsonb("referrals").$type<Partial<Record<ReferralKey, PackMark>>>().notNull(),
    insurerPolicy: text("insurer_policy"),
    legalReview: boolean("legal_review").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("obligation_cases_incident").on(t.incidentId)],
);

export const obligationDrafts = pgTable("obligation_drafts", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
  caseId: uuid("case_id").notNull().references(() => obligationCases.id, { onDelete: "cascade" }),
  kind: text("kind").notNull(),
  body: text("body").notNull(),
  authorId: text("author_id"),
  authorName: text("author_name").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/** SOCI and ransomware payment reporting clocks. One per kind per incident; reminders stop once reported. */
export const reportingClocks = pgTable(
  "reporting_clocks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
    caseId: uuid("case_id").notNull().references(() => obligationCases.id, { onDelete: "cascade" }),
    kind: text("kind").$type<ClockKind>().notNull(),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
    dueAt: timestamp("due_at", { withTimezone: true }).notNull(),
    timeZone: text("time_zone").notNull(),
    startedBy: text("started_by").notNull(),
    reportedAt: timestamp("reported_at", { withTimezone: true }),
    reportedBy: text("reported_by"),
    reportRef: text("report_ref"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("reporting_clocks_incident_kind").on(t.incidentId, t.kind)],
);
