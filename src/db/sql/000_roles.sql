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
END $$;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

GRANT USAGE ON SCHEMA public TO blaksoc_app, blaksoc_system;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO blaksoc_app, blaksoc_system;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO blaksoc_app, blaksoc_system;
-- Audit is append-only for both.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM blaksoc_app, blaksoc_system;
