import { integer, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import type { DmarcAggregate } from "@/lib/email/dmarc";
import type { PostureParse } from "@/lib/email/posture";
import { tenants } from "./platform";
import { assets } from "./security";

export const monitoredDomains = pgTable(
  "monitored_domains",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    source: text("source").notNull(),
    verificationToken: text("verification_token").notNull(),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    attestedAt: timestamp("attested_at", { withTimezone: true }),
    attestedBy: text("attested_by"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("monitored_domains_tenant_name").on(t.tenantId, t.name)],
);

export const emailPostureChecks = pgTable("email_posture_checks", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  domainId: uuid("domain_id").notNull().references(() => monitoredDomains.id, { onDelete: "cascade" }),
  checkedAt: timestamp("checked_at", { withTimezone: true }).notNull(),
  score: integer("score").notNull(),
  detail: jsonb("detail").$type<PostureParse>().notNull(),
});

export const dmarcReports = pgTable(
  "dmarc_reports",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    domainName: text("domain_name").notNull(),
    reportId: text("report_id").notNull(),
    summary: jsonb("summary").$type<DmarcAggregate>().notNull(),
    ingestedAt: timestamp("ingested_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("dmarc_reports_tenant_report").on(t.tenantId, t.reportId)],
);

export const credentialExposures = pgTable(
  "credential_exposures",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    identity: text("identity").notNull(),
    breach: text("breach").notNull(),
    source: text("source").notNull(),
    observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
    dataClasses: text("data_classes").array().notNull(),
    assetId: uuid("asset_id").references(() => assets.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("credential_exposures_dedupe").on(t.tenantId, t.identity, t.breach, t.source)],
);
