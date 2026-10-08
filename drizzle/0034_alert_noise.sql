-- Alert fatigue, phase 1: noise rules, the passive lane, the disposition-memory index and the tuning API
-- for Hermes (src/lib/tuning, src/lib/services/tuning.ts, src/lib/services/hermes.ts). RLS for the new
-- tables is in src/db/sql/005_rls.sql.
CREATE TABLE IF NOT EXISTS "noise_rules" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "source" text NOT NULL,
  "rule_id" text NOT NULL,
  "asset_id" uuid REFERENCES "assets"("id") ON DELETE cascade,
  "hostname" text,
  "title_pattern" text,
  "max_severity" "severity",
  "reason" text NOT NULL,
  "evidence" text,
  "status" text DEFAULT 'proposed' NOT NULL,
  "created_by" text,
  "created_by_kind" text NOT NULL,
  "approved_by" text,
  "decided_at" timestamp with time zone,
  "expires_at" timestamp with time zone NOT NULL,
  "hit_count" integer DEFAULT 0 NOT NULL,
  "last_hit_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "noise_rules_status" CHECK ("status" IN ('proposed', 'active', 'expired', 'rejected')),
  CONSTRAINT "noise_rules_created_by_kind" CHECK ("created_by_kind" IN ('user', 'service'))
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "noise_rules_match" ON "noise_rules" ("tenant_id", "source", "rule_id") WHERE "status" = 'active';
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "noise_rules_tenant" ON "noise_rules" ("tenant_id", "status", "created_at");
--> statement-breakpoint
-- Constant defaults: no table rewrite on Postgres 11+.
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "lane" text DEFAULT 'active' NOT NULL;
--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "passive_reason" text;
--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "noise_rule_id" uuid REFERENCES "noise_rules"("id") ON DELETE set null;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "alerts_disposition" ON "alerts" ("tenant_id", "source", "rule_id", "occurred_at");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "alerts_passive" ON "alerts" ("tenant_id", "occurred_at") WHERE "lane" = 'passive';
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "tuning_patterns" (
  "id" text PRIMARY KEY NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "source" text NOT NULL,
  "rule_id" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "tuning_patterns_key" ON "tuning_patterns" ("tenant_id", "source", "rule_id");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "tuning_actions" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "kind" text NOT NULL,
  "pattern_id" text NOT NULL,
  "source" text NOT NULL,
  "rule_id" text NOT NULL,
  "params" jsonb DEFAULT '{}'::jsonb NOT NULL,
  "affected_count" integer DEFAULT 0 NOT NULL,
  "actor_id" text NOT NULL,
  "noise_rule_id" uuid REFERENCES "noise_rules"("id") ON DELETE set null,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "reversible_until" timestamp with time zone,
  "undone_at" timestamp with time zone,
  "undone_by" text,
  "undone_by_kind" text,
  CONSTRAINT "tuning_actions_kind" CHECK ("kind" IN ('annotate', 'close', 'noise_rule', 'purge'))
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "tuning_actions_pattern" ON "tuning_actions" ("tenant_id", "source", "rule_id", "created_at");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "tuning_actions_created" ON "tuning_actions" ("created_at");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "pattern_annotations" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "pattern_id" text NOT NULL,
  "source" text NOT NULL,
  "rule_id" text NOT NULL,
  "text" text NOT NULL,
  "confidence" text NOT NULL,
  "created_by" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "pattern_annotations_confidence" CHECK ("confidence" IN ('low', 'medium', 'high'))
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "pattern_annotations_pattern" ON "pattern_annotations" ("tenant_id", "source", "rule_id", "created_at");
--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "tuning_action_id" uuid REFERENCES "tuning_actions"("id") ON DELETE set null;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "alerts_tuning_action" ON "alerts" ("tuning_action_id") WHERE "tuning_action_id" IS NOT NULL;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "hermes_reports" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "period_start" timestamp with time zone NOT NULL,
  "period_end" timestamp with time zone NOT NULL,
  "markdown" text NOT NULL,
  "stats" jsonb NOT NULL,
  "created_by" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "hermes_reports_created" ON "hermes_reports" ("created_at");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "hermes_memory_notes" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "kind" text NOT NULL,
  "text" text NOT NULL,
  "created_by" text,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "hermes_memory_notes_kind" CHECK ("kind" IN ('model', 'outcome', 'human'))
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "hermes_memory_notes_kind" ON "hermes_memory_notes" ("kind", "created_at");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "platform_settings" (
  "key" text PRIMARY KEY NOT NULL,
  "value" jsonb NOT NULL,
  "updated_by" text,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
