ALTER TYPE "tenant_kind" ADD VALUE IF NOT EXISTS 'partner';
ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "parent_id" uuid;
ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "brand_name" text;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'tenants_parent_id_tenants_id_fk'
  ) THEN
    ALTER TABLE "tenants"
      ADD CONSTRAINT "tenants_parent_id_tenants_id_fk"
      FOREIGN KEY ("parent_id") REFERENCES "tenants"("id") ON DELETE RESTRICT;
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS "tenants_parent_idx" ON "tenants" ("parent_id");

CREATE TABLE IF NOT EXISTS "partner_consents" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "customer_tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "partner_tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "consented_by" text NOT NULL,
  "consented_at" timestamp with time zone DEFAULT now() NOT NULL,
  "statement" text NOT NULL,
  "revoked_at" timestamp with time zone
);
CREATE UNIQUE INDEX IF NOT EXISTS "partner_consents_pair" ON "partner_consents" ("customer_tenant_id", "partner_tenant_id");

CREATE TABLE IF NOT EXISTS "partner_escalations" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "partner_tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE CASCADE,
  "incident_id" uuid,
  "note" text NOT NULL,
  "created_by" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
CREATE INDEX IF NOT EXISTS "partner_escalations_tenant" ON "partner_escalations" ("tenant_id", "created_at");
