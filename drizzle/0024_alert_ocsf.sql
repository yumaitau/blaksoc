-- OCSF records for each alert (src/lib/ocsf). Null on alerts ingested before this migration
-- and on alerts written outside the ingest pipeline.
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "ocsf" jsonb;
--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "ocsf_source_event" jsonb;
--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "normalization_version" text;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "alerts_ocsf_source_class" ON "alerts" ("tenant_id", ((("ocsf_source_event"->>'class_uid'))::int)) WHERE "ocsf_source_event" IS NOT NULL;
