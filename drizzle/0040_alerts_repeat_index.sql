-- Repeat count at ingest filters on tenant, asset, rule and a 24h window. Without this index it walked
-- alerts_occurred and filtered every alert in the window: a 06-11-2026 flood (one host, one rule, 200k+ alerts)
-- turned each ingest into a ~180 ms scan and kept the database at ~50% CPU.
-- Production: create this CONCURRENTLY before deploying (see PR); IF NOT EXISTS then makes this a no-op.
CREATE INDEX IF NOT EXISTS "alerts_repeat" ON "alerts" ("tenant_id", "asset_id", "rule_id", "occurred_at");
