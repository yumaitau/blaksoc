ALTER TABLE "sites" ADD COLUMN IF NOT EXISTS "silent_hours" integer;--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "health_baselines" (
  "tenant_id" uuid PRIMARY KEY REFERENCES "tenants"("id") ON DELETE cascade,
  "technique_count" integer NOT NULL,
  "rule_count" integer NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
