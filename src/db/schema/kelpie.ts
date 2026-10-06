import { index, integer, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { incidents } from "./security";
import { tenants } from "./platform";

/**
 * Link from a blakSOC incident to its Kelpie case. Kelpie owns case work; blakSOC mirrors status for the
 * portal, paging, and breach clocks. A row with no caseId is a push that has not succeeded yet.
 */
export const kelpieCases = pgTable(
  "kelpie_cases",
  {
    incidentId: uuid("incident_id").primaryKey().references(() => incidents.id, { onDelete: "cascade" }),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    integrationId: uuid("integration_id").notNull(),
    caseId: text("case_id"),
    caseNumber: text("case_number"),
    caseUrl: text("case_url"),
    /** Kelpie case version last mirrored. A change means Kelpie moved on. */
    version: integer("version"),
    observablesPushedAt: timestamp("observables_pushed_at", { withTimezone: true }),
    attempts: integer("attempts").notNull().default(0),
    lastError: text("last_error"),
    nextAttemptAt: timestamp("next_attempt_at", { withTimezone: true }).notNull().defaultNow(),
    pushedAt: timestamp("pushed_at", { withTimezone: true }),
    syncedAt: timestamp("synced_at", { withTimezone: true }),
  },
  (t) => [index("kelpie_cases_tenant").on(t.tenantId, t.nextAttemptAt)],
);
