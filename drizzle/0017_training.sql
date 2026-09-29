CREATE TABLE IF NOT EXISTS "training_attempts" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "scenario_id" text NOT NULL,
  "trainee_id" text NOT NULL,
  "trainee_name" text NOT NULL,
  "actions" text[] DEFAULT '{}'::text[] NOT NULL,
  "hints_used" integer DEFAULT 0 NOT NULL,
  "score" integer DEFAULT 0 NOT NULL,
  "status" text DEFAULT 'open' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "training_attempts_tenant" ON "training_attempts" ("tenant_id", "trainee_id");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "training_cosigns" (
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "trainee_id" text NOT NULL,
  "mentor_id" text NOT NULL,
  "cosigned_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "training_cosigns_tenant_id_trainee_id_pk" PRIMARY KEY ("tenant_id", "trainee_id")
);
