CREATE TABLE IF NOT EXISTS "onboarding_drafts" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "owner_user_id" text NOT NULL,
  "status" text DEFAULT 'draft' NOT NULL,
  "step" text DEFAULT 'org' NOT NULL,
  "org" jsonb,
  "contacts" jsonb,
  "stack" jsonb,
  "connect" jsonb,
  "governance" jsonb,
  "plan" jsonb,
  "tenant_id" uuid REFERENCES "tenants"("id") ON DELETE cascade,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
-- A setup summary is not an incident, so the delivery row may omit incident_id.
ALTER TABLE "notification_deliveries" ALTER COLUMN "incident_id" DROP NOT NULL;
