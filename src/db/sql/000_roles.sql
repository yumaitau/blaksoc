-- Application role: never owns tables, so RLS always applies to it.
-- System role: worker jobs and the few web paths that act before a tenant scope exists
-- (onboarding, provider lookups). It owns nothing and has no BYPASSRLS: it reaches rows
-- through the system_access policies in 020_system_access.sql, so it cannot run DDL,
-- disable triggers, change policies or rewrite the audit log. Owner credentials stay with
-- the migration job.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'blaksoc_app') THEN
    CREATE ROLE blaksoc_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'blaksoc_system') THEN
    CREATE ROLE blaksoc_system LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  -- Backup role: read-only, bypasses RLS so pg_dump copies every tenant's rows (tables FORCE RLS, and the
  -- owner may not bypass it, e.g. the RDS master). Login only when migrate.ts has a password for it.
  -- Its grants are in 999_backup_access.sql, which runs after every file that creates a table.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'blaksoc_backup') THEN
    CREATE ROLE blaksoc_backup NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

GRANT USAGE ON SCHEMA public TO blaksoc_app, blaksoc_system;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO blaksoc_app, blaksoc_system;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO blaksoc_app, blaksoc_system;
-- Audit is append-only for both.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM blaksoc_app, blaksoc_system;
