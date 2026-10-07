-- Service identities and their short-lived bearer tokens for /api/v1 (#69).
-- RLS policies are in src/db/sql/005_rls.sql, which runs after these migrations.
CREATE TABLE IF NOT EXISTS "service_identities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid REFERENCES "tenants"("id") ON DELETE cascade,
	"name" text NOT NULL,
	"scopes" text[] DEFAULT '{}' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"secret_hash" text NOT NULL,
	"secret_rotated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "service_tokens" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"identity_id" uuid NOT NULL REFERENCES "service_identities"("id") ON DELETE cascade,
	"tenant_id" uuid REFERENCES "tenants"("id") ON DELETE cascade,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "service_tokens_identity" ON "service_tokens" ("identity_id");
