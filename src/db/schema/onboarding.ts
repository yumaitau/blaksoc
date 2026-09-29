import { jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import type { ConnectDraft, ContactsDraft, GovernanceDraft, OrgDraft, PlanDraft, StackDraft } from "@/lib/onboarding/types";
import { tenants } from "./platform";

/**
 * Exists before the tenant row. Kept out of the tenant_id RLS policy on purpose:
 * a null tenant_id would be invisible, and the app role is denied entirely.
 */
export const onboardingDrafts = pgTable("onboarding_drafts", {
  id: uuid("id").primaryKey().defaultRandom(),
  ownerUserId: text("owner_user_id").notNull(),
  status: text("status").notNull().default("draft"),
  step: text("step").notNull().default("org"),
  org: jsonb("org").$type<OrgDraft>(),
  contacts: jsonb("contacts").$type<ContactsDraft>(),
  stack: jsonb("stack").$type<StackDraft>(),
  connect: jsonb("connect").$type<ConnectDraft>(),
  governance: jsonb("governance").$type<GovernanceDraft>(),
  plan: jsonb("plan").$type<PlanDraft>(),
  tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});
