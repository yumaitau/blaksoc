import { pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { sites, tenants } from "./platform";
import { assets } from "./security";

export const enrolmentTokens = pgTable(
  "enrolment_tokens",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    siteId: uuid("site_id").references(() => sites.id, { onDelete: "set null" }),
    tokenHash: text("token_hash").notNull(),
    /** AES-GCM ciphertext. Cleared on revoke. Plaintext is never stored. */
    tokenCiphertext: text("token_ciphertext"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("enrolment_tokens_hash").on(t.tokenHash)],
);

export const coverageTasks = pgTable(
  "coverage_tasks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    assetId: uuid("asset_id").notNull().references(() => assets.id, { onDelete: "cascade" }),
    hostname: text("hostname").notNull(),
    status: text("status").notNull().default("open"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("coverage_tasks_tenant_asset").on(t.tenantId, t.assetId)],
);
