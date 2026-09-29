import { boolean, index, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

/** A practice campaign the customer admin consented to. No mail is sent from this row. */
export const awarenessCampaigns = pgTable(
  "awareness_campaigns",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    consented: boolean("consented").notNull().default(false),
    scheduledAt: timestamp("scheduled_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("awareness_campaigns_tenant").on(t.tenantId, t.scheduledAt)],
);

/** A fixture click on a practice campaign. The board report never reads the person label. */
export const awarenessClicks = pgTable(
  "awareness_clicks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    campaignId: uuid("campaign_id").notNull().references(() => awarenessCampaigns.id, { onDelete: "cascade" }),
    personLabel: text("person_label").notNull(),
    clickedAt: timestamp("clicked_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("awareness_clicks_tenant").on(t.tenantId, t.clickedAt)],
);
