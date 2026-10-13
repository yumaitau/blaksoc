import { index, integer, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import type { WedgetailE8, WedgetailIsm, WedgetailMitre } from "@/lib/wedgetail/posture";
import { tenants } from "./platform";
import { integrations } from "./security";

/**
 * Latest ISM control status, Essential Eight assessment summary and ATT&CK rule coverage pulled from a customer's Wedgetail install over MCP.
 * One row per integration; the last good snapshot stays when a later pull fails.
 */
export const wedgetailPosture = pgTable(
  "wedgetail_posture",
  {
    integrationId: uuid("integration_id").primaryKey().references(() => integrations.id, { onDelete: "cascade" }),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    ism: jsonb("ism").$type<WedgetailIsm>(),
    mitre: jsonb("mitre").$type<WedgetailMitre>(),
    /** Null when the install predates essential_eight_summary or the token's owner is scoped. */
    e8: jsonb("e8").$type<WedgetailE8>(),
    fetchedAt: timestamp("fetched_at", { withTimezone: true }),
    attemptedAt: timestamp("attempted_at", { withTimezone: true }).notNull().defaultNow(),
    attempts: integer("attempts").notNull().default(0),
    nextAttemptAt: timestamp("next_attempt_at", { withTimezone: true }).notNull().defaultNow(),
    lastError: text("last_error"),
  },
  (t) => [index("wedgetail_posture_tenant").on(t.tenantId)],
);
