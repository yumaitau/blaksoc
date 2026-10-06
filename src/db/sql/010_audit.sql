-- Hash chain: each row commits to the previous row's hash, so any edit or deletion
-- (e.g. by a DBA bypassing the triggers) is detectable by verifyAuditChain().
-- Version 1 rows (before 0022) do not cover ip. Version 2 covers ip and the version itself,
-- so a row cannot be downgraded to drop its ip from the hash.
CREATE OR REPLACE FUNCTION audit_log_row_hash(prev text, r audit_log) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = public AS $$
  SELECT encode(digest(
    prev || '|' || r.id::text || '|' || to_char(r.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') || '|' ||
    coalesce(r.actor_id, '') || '|' || r.actor_kind || '|' || coalesce(r.tenant_id::text, '') || '|' ||
    r.action || '|' || coalesce(r.target_type, '') || '|' || coalesce(r.target_id, '') || '|' ||
    coalesce(r.detail::text, '') ||
    CASE WHEN r.hash_version >= 2 THEN '|v' || r.hash_version::text || '|' || coalesce(r.ip, '') ELSE '' END,
    'sha256'), 'hex')
$$;
CREATE OR REPLACE FUNCTION audit_log_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  prev text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('audit_log_chain'));
  SELECT hash INTO prev FROM audit_log ORDER BY id DESC LIMIT 1;
  NEW.prev_hash := coalesce(prev, 'GENESIS');
  NEW.hash_version := 2;
  NEW.hash := audit_log_row_hash(NEW.prev_hash, NEW);
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END $$;

DROP TRIGGER IF EXISTS audit_log_chain ON audit_log;
CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_chain();
DROP TRIGGER IF EXISTS audit_log_immutable ON audit_log;
CREATE TRIGGER audit_log_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- Chain verification must see every row regardless of caller scope.
CREATE OR REPLACE FUNCTION audit_log_verify() RETURNS TABLE (ok boolean, checked bigint, first_bad_id bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  r audit_log;
  prev text := 'GENESIS';
  expected text;
  n bigint := 0;
BEGIN
  FOR r IN SELECT * FROM audit_log ORDER BY id LOOP
    n := n + 1;
    expected := audit_log_row_hash(prev, r);
    IF r.prev_hash IS DISTINCT FROM prev OR r.hash IS DISTINCT FROM expected THEN
      RETURN QUERY SELECT false, n, r.id; RETURN;
    END IF;
    prev := r.hash;
  END LOOP;
  RETURN QUERY SELECT true, n, NULL::bigint;
END $$;
GRANT EXECUTE ON FUNCTION audit_log_verify() TO blaksoc_app, blaksoc_system;
