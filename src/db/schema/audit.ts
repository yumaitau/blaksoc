import { bigserial, index, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

/**
 * Append-only, hash-chained audit trail. prev_hash/hash are set by a DB trigger and
 * UPDATE/DELETE are rejected by another (see src/db/sql/010_audit.sql).
 */
export const auditLog = pgTable(
  "audit_log",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    at: timestamp("at", { withTimezone: true }).notNull().defaultNow(),
    actorId: text("actor_id"),
    actorKind: text("actor_kind").notNull(), // user | system | playbook | ai
    tenantId: uuid("tenant_id"),
    action: text("action").notNull(),
    targetType: text("target_type"),
    targetId: text("target_id"),
    ip: text("ip"),
    detail: jsonb("detail"),
    prevHash: text("prev_hash"),
    hash: text("hash"),
  },
  (t) => [index("audit_tenant_at").on(t.tenantId, t.at)],
);
