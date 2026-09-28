-- Application role: never owns tables, so RLS always applies to it.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'blaksoc_app') THEN
    CREATE ROLE blaksoc_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

GRANT USAGE ON SCHEMA public TO blaksoc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO blaksoc_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO blaksoc_app;
-- Audit is append-only for the app.
REVOKE UPDATE, DELETE ON audit_log FROM blaksoc_app;
