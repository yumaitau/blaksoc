import { sql } from "drizzle-orm";
import { check, index, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { user } from "./auth";

/** Fixed customer scope; the issuer's current grants are checked whenever the URL is used. */
export const wallboardLinks = pgTable("wallboard_links", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  tenantIds: uuid("tenant_ids").array().notNull(),
  createdBy: text("created_by").notNull().references(() => user.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
}, (t) => [
  index("wallboard_links_created_by").on(t.createdBy),
  check("wallboard_links_scope", sql`cardinality(${t.tenantIds}) > 0`),
  check("wallboard_links_name", sql`length(${t.name}) between 1 and 80`),
  check("wallboard_links_expiry", sql`${t.expiresAt} > ${t.createdAt}`),
]);
