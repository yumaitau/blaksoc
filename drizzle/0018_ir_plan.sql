CREATE TABLE IF NOT EXISTS "ir_plans" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "version" integer NOT NULL,
  "cultural_protocol" text DEFAULT '' NOT NULL,
  "bank" text DEFAULT '' NOT NULL,
  "insurer" text DEFAULT '' NOT NULL,
  "it_provider" text DEFAULT '' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "ir_plans_tenant_version" ON "ir_plans" ("tenant_id", "version");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "ir_exercises" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "scenario_id" text NOT NULL,
  "completed_at" timestamp with time zone DEFAULT now() NOT NULL,
  "notes" text DEFAULT '' NOT NULL,
  "lessons" text DEFAULT '' NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "ir_exercises_tenant" ON "ir_exercises" ("tenant_id", "completed_at");
