CREATE TABLE IF NOT EXISTS "awareness_campaigns" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "consented" boolean DEFAULT false NOT NULL,
  "scheduled_at" timestamp with time zone NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "awareness_campaigns_tenant" ON "awareness_campaigns" ("tenant_id", "scheduled_at");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "awareness_clicks" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "campaign_id" uuid NOT NULL REFERENCES "awareness_campaigns"("id") ON DELETE cascade,
  "person_label" text NOT NULL,
  "clicked_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "awareness_clicks_tenant" ON "awareness_clicks" ("tenant_id", "clicked_at");
