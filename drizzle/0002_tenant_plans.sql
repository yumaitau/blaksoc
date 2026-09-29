CREATE TABLE IF NOT EXISTS "tenant_plans" (
  "tenant_id" uuid PRIMARY KEY NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "tier" text DEFAULT 'essentials' NOT NULL,
  "nonprofit" boolean DEFAULT false NOT NULL,
  "pilot_ends_at" timestamp with time zone,
  "discount_bps" integer DEFAULT 0 NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "usage_daily" (
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "day" date NOT NULL,
  "protected_users" integer DEFAULT 0 NOT NULL,
  "endpoints" integer DEFAULT 0 NOT NULL,
  "domains" integer DEFAULT 0 NOT NULL,
  "bytes_ingested" bigint DEFAULT 0 NOT NULL,
  "metered_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "usage_daily_pk" PRIMARY KEY ("tenant_id","day")
);--> statement-breakpoint
ALTER TABLE "integrations" ADD COLUMN IF NOT EXISTS "paused_by_plan" boolean DEFAULT false NOT NULL;--> statement-breakpoint
-- Existing customers were already collecting endpoint telemetry. A missing plan would
-- otherwise read as Essentials and pause that collection on the next worker run.
INSERT INTO "tenant_plans" ("tenant_id", "tier")
SELECT "id", 'standard' FROM "tenants" WHERE "kind" = 'customer'
ON CONFLICT ("tenant_id") DO NOTHING;
