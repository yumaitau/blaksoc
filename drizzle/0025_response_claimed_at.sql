-- When a worker claimed the action (APPROVED → EXECUTING). Lets an interrupted execution be found and failed.
ALTER TABLE "response_actions" ADD COLUMN IF NOT EXISTS "claimed_at" timestamp with time zone;
