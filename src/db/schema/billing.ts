import { bigint, boolean, date, integer, pgTable, primaryKey, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

/** Commercial plan for one customer. Missing row is treated as Essentials by the service. */
export const tenantPlans = pgTable("tenant_plans", {
  tenantId: uuid("tenant_id").primaryKey().references(() => tenants.id, { onDelete: "cascade" }),
  tier: text("tier").notNull().default("essentials"),
  nonprofit: boolean("nonprofit").notNull().default(false),
  pilotEndsAt: timestamp("pilot_ends_at", { withTimezone: true }),
  /** Explicit discount in basis points. 0 means "use the nonprofit rate when that flag is set". */
  discountBps: integer("discount_bps").notNull().default(0),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** One UTC day of usage. Users, devices and domains are a snapshot. Bytes are that day's ingest. */
export const usageDaily = pgTable(
  "usage_daily",
  {
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    day: date("day", { mode: "string" }).notNull(),
    protectedUsers: integer("protected_users").notNull().default(0),
    endpoints: integer("endpoints").notNull().default(0),
    domains: integer("domains").notNull().default(0),
    bytesIngested: bigint("bytes_ingested", { mode: "number" }).notNull().default(0),
    meteredAt: timestamp("metered_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.tenantId, t.day] })],
);
