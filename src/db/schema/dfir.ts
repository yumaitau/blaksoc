import { boolean, index, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { incidents } from "./security";
import { tenants } from "./platform";

/** One approval-gated Velociraptor collection against machines on an incident. */
export const dfirCollections = pgTable(
  "dfir_collections",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id").notNull().references(() => incidents.id, { onDelete: "cascade" }),
    assetIds: uuid("asset_ids").array().notNull(),
    artifactSets: text("artifact_sets").array().notNull(),
    lowBandwidth: boolean("low_bandwidth").notNull().default(false),
    /** pending_approval | scheduled | complete | rejected */
    status: text("status").notNull(),
    notBefore: timestamp("not_before", { withTimezone: true }).notNull(),
    approvalId: uuid("approval_id"),
    requestedBy: text("requested_by"),
    approvedBy: text("approved_by"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("dfir_collections_due").on(t.tenantId, t.status, t.notBefore)],
);

/** One hunt for an indicator across the endpoints visible in the caller's tenant. */
export const dfirHunts = pgTable("dfir_hunts", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  incidentId: uuid("incident_id").references(() => incidents.id, { onDelete: "cascade" }),
  ioc: text("ioc").notNull(),
  status: text("status").notNull(),
  matchedAssetIds: uuid("matched_asset_ids").array().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
