CREATE TABLE IF NOT EXISTS "dfir_collections" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "incident_id" uuid NOT NULL REFERENCES "incidents"("id") ON DELETE cascade,
  "asset_ids" uuid[] NOT NULL,
  "artifact_sets" text[] NOT NULL,
  "low_bandwidth" boolean DEFAULT false NOT NULL,
  "status" text NOT NULL,
  "not_before" timestamp with time zone NOT NULL,
  "approval_id" uuid,
  "requested_by" text,
  "approved_by" text,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "dfir_collections_due" ON "dfir_collections" ("tenant_id", "status", "not_before");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "dfir_hunts" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "incident_id" uuid REFERENCES "incidents"("id") ON DELETE cascade,
  "ioc" text NOT NULL,
  "status" text NOT NULL,
  "matched_asset_ids" uuid[] NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
