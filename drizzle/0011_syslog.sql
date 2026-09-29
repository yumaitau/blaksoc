CREATE TABLE IF NOT EXISTS "syslog_sources" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "name" text NOT NULL,
  "token_hash" text NOT NULL UNIQUE,
  "allow_ips" text[] DEFAULT '{}' NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "syslog_events" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "source_id" uuid NOT NULL REFERENCES "syslog_sources"("id") ON DELETE cascade,
  "vendor" text NOT NULL,
  "action" text NOT NULL,
  "line" text NOT NULL,
  "byte_len" integer NOT NULL,
  "tier" text DEFAULT 'hot' NOT NULL,
  "ingested_at" timestamp with time zone DEFAULT now() NOT NULL,
  "retain_until" timestamp with time zone NOT NULL
);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "syslog_events_tenant_hot" ON "syslog_events" ("tenant_id", "tier", "ingested_at");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "syslog_archive" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "event_id" uuid NOT NULL UNIQUE,
  "region" text NOT NULL,
  "object_key" text NOT NULL,
  "body" text NOT NULL,
  "archived_at" timestamp with time zone DEFAULT now() NOT NULL
);
