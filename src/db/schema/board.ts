import { pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

/** Optional note, image, and period the organisation chose for the board one-pager. */
export const boardBriefs = pgTable("board_briefs", {
  tenantId: uuid("tenant_id").primaryKey().references(() => tenants.id, { onDelete: "cascade" }),
  preamble: text("preamble"),
  imageMime: text("image_mime"),
  imageData: text("image_data"),
  span: text("span").notNull().default("month"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});
