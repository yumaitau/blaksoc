CREATE TABLE IF NOT EXISTS "monitored_domains" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "name" text NOT NULL,
  "source" text NOT NULL,
  "verification_token" text NOT NULL,
  "verified_at" timestamp with time zone,
  "attested_at" timestamp with time zone,
  "attested_by" text,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "monitored_domains_tenant_name" ON "monitored_domains" ("tenant_id", "name");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "email_posture_checks" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "domain_id" uuid NOT NULL REFERENCES "monitored_domains"("id") ON DELETE cascade,
  "checked_at" timestamp with time zone NOT NULL,
  "score" integer NOT NULL,
  "detail" jsonb NOT NULL
);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "dmarc_reports" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "domain_name" text NOT NULL,
  "report_id" text NOT NULL,
  "summary" jsonb NOT NULL,
  "ingested_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "dmarc_reports_tenant_report" ON "dmarc_reports" ("tenant_id", "report_id");--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "credential_exposures" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "identity" text NOT NULL,
  "breach" text NOT NULL,
  "source" text NOT NULL,
  "observed_at" timestamp with time zone NOT NULL,
  "data_classes" text[] NOT NULL,
  "asset_id" uuid REFERENCES "assets"("id") ON DELETE set null,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "credential_exposures_dedupe" ON "credential_exposures" ("tenant_id", "identity", "breach", "source");--> statement-breakpoint
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "evidence" jsonb;
