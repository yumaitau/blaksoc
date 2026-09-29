import { index, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import type { EscalationStep } from "@/lib/portal/escalation";
import { incidents } from "./security";
import { tenants } from "./platform";

/** Per-tenant severity, channel, and contact order. Retries stop once the customer acknowledges. */
export const escalationPolicies = pgTable("escalation_policies", {
  tenantId: uuid("tenant_id").primaryKey().references(() => tenants.id, { onDelete: "cascade" }),
  steps: jsonb("steps").$type<EscalationStep[]>().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** One attempt to deliver an SMS, voice call, or email. Status is the source for rate limits and audit. */
export const notificationDeliveries = pgTable(
  "notification_deliveries",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id").references(() => incidents.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(),
    channel: text("channel").notNull(),
    destination: text("destination").notNull(),
    status: text("status").notNull(),
    providerRef: text("provider_ref"),
    detail: jsonb("detail").$type<Record<string, unknown>>(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("notification_deliveries_incident").on(t.tenantId, t.incidentId, t.createdAt)],
);
