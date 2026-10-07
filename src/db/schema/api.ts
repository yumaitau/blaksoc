import { boolean, index, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

/**
 * Machine caller of /api/v1. Bound to one tenant, or platform-wide when tenant_id is null.
 * The id is the OAuth client_id; only a SHA-256 of the client secret is stored.
 */
export const serviceIdentities = pgTable("service_identities", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  /** Permissions from permissions.ts. Never more than the creator held. */
  scopes: text("scopes").array().notNull().default([]),
  enabled: boolean("enabled").notNull().default(true),
  secretHash: text("secret_hash").notNull(),
  secretRotatedAt: timestamp("secret_rotated_at", { withTimezone: true }).notNull().defaultNow(),
  /** Terminal. A revoked identity cannot be re-enabled or rotated. */
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdBy: text("created_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
});

/** Opaque short-lived bearer tokens, stored as SHA-256. tenant_id mirrors the identity for RLS. */
export const serviceTokens = pgTable(
  "service_tokens",
  {
    tokenHash: text("token_hash").primaryKey(),
    identityId: uuid("identity_id").notNull().references(() => serviceIdentities.id, { onDelete: "cascade" }),
    tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("service_tokens_identity").on(t.identityId)],
);
