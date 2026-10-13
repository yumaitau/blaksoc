-- Wedgetail's own Essential Eight assessment summary (maturity and requirement counts per strategy),
-- pulled over MCP with ISM status and ATT&CK coverage (src/lib/services/wedgetail-posture.ts).
ALTER TABLE "wedgetail_posture" ADD COLUMN IF NOT EXISTS "e8" jsonb;
