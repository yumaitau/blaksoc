-- blaksoc_system reaches every row of every RLS table through a role-specific policy instead
-- of BYPASSRLS or table ownership. Runs after every other file, so tables that gain RLS later
-- are covered on the next migration. Grants still apply: audit_log stays insert/select only.
DO $$
DECLARE t text;
BEGIN
  FOR t IN
    SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS system_access ON %I', t);
    EXECUTE format('CREATE POLICY system_access ON %I TO blaksoc_system USING (true) WITH CHECK (true)', t);
  END LOOP;
END $$;
