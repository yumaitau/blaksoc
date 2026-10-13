-- ISM control status and ATT&CK rule coverage pulled from each Wedgetail install's MCP endpoint
-- (src/lib/services/wedgetail-posture.ts). Tenant-isolated in src/db/sql/005_rls.sql.
CREATE TABLE IF NOT EXISTS "wedgetail_posture" (
  "integration_id" uuid PRIMARY KEY NOT NULL REFERENCES "integrations"("id") ON DELETE cascade,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "ism" jsonb,
  "mitre" jsonb,
  "fetched_at" timestamp with time zone,
  "attempted_at" timestamp with time zone DEFAULT now() NOT NULL,
  "attempts" integer DEFAULT 0 NOT NULL,
  "next_attempt_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_error" text
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "wedgetail_posture_tenant" ON "wedgetail_posture" ("tenant_id");
