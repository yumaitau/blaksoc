CREATE INDEX IF NOT EXISTS "alerts_tenant_occurred" ON "alerts" ("tenant_id", "occurred_at");
