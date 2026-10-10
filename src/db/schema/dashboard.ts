import { sql } from "drizzle-orm";
import { check, jsonb, pgTable, text, timestamp } from "drizzle-orm/pg-core";
import type { DashboardWidget } from "@/lib/dashboard/layout";
import { user } from "./auth";

/** One SOC dashboard arrangement per analyst. RLS requires app.user_id in the same transaction. */
export const dashboardLayouts = pgTable(
  "dashboard_layouts",
  {
    userId: text("user_id").primaryKey().references(() => user.id, { onDelete: "cascade" }),
    widgets: jsonb("widgets").$type<DashboardWidget[]>().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    check("dashboard_layouts_widgets", sql`jsonb_typeof(${t.widgets}) = 'array' AND jsonb_array_length(${t.widgets}) BETWEEN 1 AND 40`),
  ],
);
