-- Alert poll cursor moves from Redis to Postgres so a Redis loss neither replays nor skips a provider window.
ALTER TABLE "integrations" ADD COLUMN IF NOT EXISTS "poll_cursor" text;
