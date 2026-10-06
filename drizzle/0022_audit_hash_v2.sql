-- Existing rows keep version 1 (hash without ip). The chain trigger writes version 2.
ALTER TABLE "audit_log" ADD COLUMN IF NOT EXISTS "hash_version" smallint DEFAULT 1 NOT NULL;
