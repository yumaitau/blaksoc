-- Steps a run started with. Editing a playbook no longer changes runs already in flight.
-- Null on runs started before this migration; those fall back to the live playbook.
ALTER TABLE "playbook_runs" ADD COLUMN IF NOT EXISTS "steps" jsonb;
