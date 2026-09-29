CREATE TABLE IF NOT EXISTS "obligation_cases" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "incident_id" uuid NOT NULL REFERENCES "incidents"("id") ON DELETE cascade,
  "started_at" timestamp with time zone NOT NULL,
  "due_at" timestamp with time zone NOT NULL,
  "applicability" jsonb NOT NULL,
  "serious_harm" text,
  "serious_harm_rationale" text,
  "serious_harm_by" text,
  "serious_harm_at" timestamp with time zone,
  "decision" text,
  "decision_rationale" text,
  "decision_by" text,
  "decision_at" timestamp with time zone,
  "referrals" jsonb NOT NULL,
  "insurer_policy" text,
  "legal_review" boolean DEFAULT false NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "obligation_cases_incident" ON "obligation_cases" ("incident_id");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "obligation_drafts" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "incident_id" uuid NOT NULL REFERENCES "incidents"("id") ON DELETE cascade,
  "case_id" uuid NOT NULL REFERENCES "obligation_cases"("id") ON DELETE cascade,
  "kind" text NOT NULL,
  "body" text NOT NULL,
  "author_id" text,
  "author_name" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "obligation_drafts_case" ON "obligation_drafts" ("case_id");
