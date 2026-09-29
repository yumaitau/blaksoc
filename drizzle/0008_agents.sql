ALTER TABLE "sites" ADD COLUMN IF NOT EXISTS "bandwidth_profile" text DEFAULT 'standard' NOT NULL;--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "enrolment_tokens" (
  "id" uuid PRIMARY KEY NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "site_id" uuid REFERENCES "sites"("id") ON DELETE set null,
  "token_hash" text NOT NULL,
  "token_ciphertext" text,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "revoked_at" timestamp with time zone
);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "enrolment_tokens_hash" ON "enrolment_tokens" ("token_hash");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "coverage_tasks" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "asset_id" uuid NOT NULL REFERENCES "assets"("id") ON DELETE cascade,
  "hostname" text NOT NULL,
  "status" text DEFAULT 'open' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "resolved_at" timestamp with time zone
);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "coverage_tasks_tenant_asset" ON "coverage_tasks" ("tenant_id", "asset_id");
