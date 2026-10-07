-- Correlation engine (src/lib/correlation) and automatic incident grouping. RLS for the new
-- tables is in src/db/sql/005_rls.sql.
CREATE TABLE IF NOT EXISTS "correlation_findings" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "rule_id" text NOT NULL,
  "rule_version" integer NOT NULL,
  "dedupe_key" text NOT NULL,
  "entity" jsonb NOT NULL,
  "alert_id" uuid REFERENCES "alerts"("id") ON DELETE set null,
  "first_at" timestamp with time zone NOT NULL,
  "last_at" timestamp with time zone NOT NULL,
  "matches" jsonb NOT NULL,
  "explanation" text[] NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "correlation_findings_dedupe" ON "correlation_findings" ("tenant_id", "dedupe_key");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "correlation_findings_tenant" ON "correlation_findings" ("tenant_id", "created_at");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "correlation_rule_settings" (
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "rule_id" text NOT NULL,
  "enabled" boolean NOT NULL,
  "updated_by" text,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  PRIMARY KEY ("tenant_id", "rule_id")
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "correlation_cursors" (
  "tenant_id" uuid PRIMARY KEY NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "evaluated_through" timestamp with time zone NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "incident_group_exclusions" (
  "alert_id" uuid PRIMARY KEY NOT NULL REFERENCES "alerts"("id") ON DELETE cascade,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "incident_id" uuid REFERENCES "incidents"("id") ON DELETE set null,
  "actor_id" text,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
-- Existing links were made by analysts or playbooks.
ALTER TABLE "incident_alerts" ADD COLUMN IF NOT EXISTS "origin" text DEFAULT 'manual' NOT NULL;
--> statement-breakpoint
ALTER TABLE "incident_alerts" ADD COLUMN IF NOT EXISTS "reason" jsonb;
--> statement-breakpoint
ALTER TABLE "incident_alerts" ADD COLUMN IF NOT EXISTS "prior_status" "alert_status";
--> statement-breakpoint
ALTER TABLE "incident_alerts" ADD COLUMN IF NOT EXISTS "linked_at" timestamp with time zone DEFAULT now() NOT NULL;
--> statement-breakpoint
ALTER TABLE "incidents" ADD COLUMN IF NOT EXISTS "grouping_key" text;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "incidents_grouping_key" ON "incidents" ("tenant_id", "grouping_key") WHERE "grouping_key" IS NOT NULL;
