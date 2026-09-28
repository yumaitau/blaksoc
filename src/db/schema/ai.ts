import { integer, jsonb, pgTable, text, timestamp, uuid, index } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

export type Citation = { type: string; id: string; label: string };

export const aiConversations = pgTable("ai_conversations", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  userId: text("user_id").notNull(),
  title: text("title").notNull(),
  subject: jsonb("subject").$type<{ type: string; id: string }>(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const aiMessages = pgTable("ai_messages", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  conversationId: uuid("conversation_id").notNull().references(() => aiConversations.id, { onDelete: "cascade" }),
  role: text("role").notNull(), // user | assistant | tool
  content: text("content").notNull(),
  toolCalls: jsonb("tool_calls").$type<{ name: string; args: unknown; resultRefs: Citation[] }[]>(),
  citations: jsonb("citations").$type<Citation[]>(),
  /** Citations the model asserted that did not come from a tool result. */
  unverifiedCitations: jsonb("unverified_citations").$type<string[]>(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Every model call: which provider/region processed which tenant's data and why. */
export const aiInvocations = pgTable(
  "ai_invocations",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    userId: text("user_id"),
    provider: text("provider").notNull(),
    model: text("model").notNull(),
    region: text("region"),
    purpose: text("purpose").notNull(),
    policyDecision: text("policy_decision").notNull(),
    inputTokens: integer("input_tokens"),
    outputTokens: integer("output_tokens"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("ai_invocations_tenant").on(t.tenantId, t.createdAt)],
);

export const reports = pgTable("reports", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  kind: text("kind").notNull(),
  title: text("title").notNull(),
  periodStart: timestamp("period_start", { withTimezone: true }).notNull(),
  periodEnd: timestamp("period_end", { withTimezone: true }).notNull(),
  status: text("status").notNull().default("ready"),
  /** Sections tagged observed | interpretation so exports keep them visibly distinct. */
  content: jsonb("content").$type<import("../../lib/reports/types").ReportContent>().notNull(),
  generatedBy: text("generated_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
