CREATE TABLE IF NOT EXISTS "reporting_clocks" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "incident_id" uuid NOT NULL REFERENCES "incidents"("id") ON DELETE cascade,
  "case_id" uuid NOT NULL REFERENCES "obligation_cases"("id") ON DELETE cascade,
  "kind" text NOT NULL,
  "started_at" timestamp with time zone NOT NULL,
  "due_at" timestamp with time zone NOT NULL,
  "time_zone" text NOT NULL,
  "started_by" text NOT NULL,
  "reported_at" timestamp with time zone,
  "reported_by" text,
  "report_ref" text,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "reporting_clocks_incident_kind" ON "reporting_clocks" ("incident_id", "kind");--> statement-breakpoint
-- Cases started before the ransomware question existed have not answered it.
UPDATE "obligation_cases" SET "applicability" = "applicability" || '{"ransomwareReporting":"unsure"}'::jsonb
  WHERE NOT ("applicability" ? 'ransomwareReporting');
