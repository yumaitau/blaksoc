import { index, integer, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

export const AI_CAPABILITIES = ["assistant", "triage_summary"] as const;
export type AiCapability = (typeof AI_CAPABILITIES)[number];

export type SightingConsent = {
  attribution: "anonymised" | "named";
  maxTlp: "TLP:CLEAR" | "TLP:GREEN" | "TLP:AMBER" | "TLP:AMBER+STRICT" | "TLP:RED";
  /** Stewards who approved the change that granted this consent. */
  consentedBy: string[];
  consentedAt: string;
};

/**
 * Tenant data governance. Only data stewards change it. It narrows tenant settings and never widens them:
 * a setting that allows AI or sightings still needs the profile to allow it too.
 */
export type GovernanceProfile = {
  /** Storage, archives, AI inference, and intel lookups stay in Australia. */
  residencyLock: boolean;
  /** Null means nothing leaves the tenant as a sighting. */
  sightings: SightingConsent | null;
  ai: Record<AiCapability, boolean>;
};

export const MOST_PROTECTIVE: GovernanceProfile = {
  residencyLock: true,
  sightings: null,
  ai: { assistant: false, triage_summary: false },
};

/** Current profile. A tenant with no row is governed by MOST_PROTECTIVE. */
export const dataGovernance = pgTable("data_governance", {
  tenantId: uuid("tenant_id").primaryKey().references(() => tenants.id, { onDelete: "cascade" }),
  profile: jsonb("profile").$type<GovernanceProfile>().notNull(),
  changeId: uuid("change_id"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** A proposed profile. It applies once enough distinct stewards approve it. */
export const governanceChanges = pgTable(
  "governance_changes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    before: jsonb("before").$type<GovernanceProfile>().notNull(),
    after: jsonb("after").$type<GovernanceProfile>().notNull(),
    reason: text("reason").notNull(),
    /** pending, applied, rejected, or superseded. */
    status: text("status").notNull().default("pending"),
    proposedBy: text("proposed_by").notNull(),
    approvals: text("approvals").array().notNull().default([]),
    /** Distinct steward approvals needed: two when the tenant has two or more stewards. */
    required: integer("required").notNull(),
    decidedBy: text("decided_by"),
    decidedAt: timestamp("decided_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("governance_changes_tenant").on(t.tenantId, t.createdAt)],
);
