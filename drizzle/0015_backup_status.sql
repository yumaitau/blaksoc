CREATE TABLE IF NOT EXISTS "backup_status" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "asset_id" uuid NOT NULL REFERENCES "assets"("id") ON DELETE cascade,
  "integration_id" uuid NOT NULL REFERENCES "integrations"("id") ON DELETE cascade,
  "last_success_at" timestamp with time zone,
  "failed_jobs" integer DEFAULT 0 NOT NULL,
  "restore_tested_at" timestamp with time zone,
  "immutable" boolean DEFAULT false NOT NULL,
  "offline_copy" boolean DEFAULT false NOT NULL,
  "stale" boolean DEFAULT false NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "backup_status_asset" ON "backup_status" ("asset_id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "backup_status_tenant" ON "backup_status" ("tenant_id");
