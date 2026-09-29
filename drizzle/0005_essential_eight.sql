CREATE TABLE IF NOT EXISTS "e8_assessments" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "assessed_at" timestamp with time zone NOT NULL,
  "cadence_days" integer NOT NULL,
  "next_due" timestamp with time zone NOT NULL,
  "owner" text NOT NULL,
  "answers" jsonb NOT NULL,
  "result" jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "e8_tasks" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "assessment_id" uuid NOT NULL REFERENCES "e8_assessments"("id") ON DELETE cascade,
  "requirement_id" text NOT NULL,
  "strategy" text NOT NULL,
  "title" text NOT NULL,
  "owner" text NOT NULL,
  "due_at" timestamp with time zone NOT NULL,
  "priority" integer NOT NULL,
  "status" text DEFAULT 'open' NOT NULL
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "e8_assessments_tenant" ON "e8_assessments" ("tenant_id", "assessed_at" DESC);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "e8_tasks_assessment" ON "e8_tasks" ("assessment_id");
