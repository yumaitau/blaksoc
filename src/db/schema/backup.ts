import { boolean, index, integer, pgTable, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { assets, integrations } from "./security";
import { tenants } from "./platform";

/** Last backup signals for one protected system. */
export const backupStatus = pgTable(
  "backup_status",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    assetId: uuid("asset_id").notNull().references(() => assets.id, { onDelete: "cascade" }),
    integrationId: uuid("integration_id").notNull().references(() => integrations.id, { onDelete: "cascade" }),
    lastSuccessAt: timestamp("last_success_at", { withTimezone: true }),
    failedJobs: integer("failed_jobs").notNull().default(0),
    restoreTestedAt: timestamp("restore_tested_at", { withTimezone: true }),
    immutable: boolean("immutable").notNull().default(false),
    offlineCopy: boolean("offline_copy").notNull().default(false),
    stale: boolean("stale").notNull().default(false),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("backup_status_asset").on(t.assetId), index("backup_status_tenant").on(t.tenantId)],
);
