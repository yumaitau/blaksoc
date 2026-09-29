CREATE TABLE IF NOT EXISTS "escalation_policies" (
  "tenant_id" uuid PRIMARY KEY NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "steps" jsonb NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "notification_deliveries" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "incident_id" uuid NOT NULL REFERENCES "incidents"("id") ON DELETE cascade,
  "provider" text NOT NULL,
  "channel" text NOT NULL,
  "destination" text NOT NULL,
  "status" text NOT NULL,
  "provider_ref" text,
  "detail" jsonb,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "notification_deliveries_incident" ON "notification_deliveries" ("tenant_id", "incident_id", "created_at");
