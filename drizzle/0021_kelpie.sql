CREATE TABLE IF NOT EXISTS "kelpie_cases" (
  "incident_id" uuid PRIMARY KEY NOT NULL REFERENCES "incidents"("id") ON DELETE cascade,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "integration_id" uuid NOT NULL,
  "case_id" text,
  "case_number" text,
  "case_url" text,
  "version" integer,
  "observables_pushed_at" timestamp with time zone,
  "attempts" integer DEFAULT 0 NOT NULL,
  "last_error" text,
  "next_attempt_at" timestamp with time zone DEFAULT now() NOT NULL,
  "pushed_at" timestamp with time zone,
  "synced_at" timestamp with time zone
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "kelpie_cases_tenant" ON "kelpie_cases" ("tenant_id", "next_attempt_at");
--> statement-breakpoint
ALTER TABLE "incident_tasks" ADD COLUMN IF NOT EXISTS "kelpie_comment_id" text;
