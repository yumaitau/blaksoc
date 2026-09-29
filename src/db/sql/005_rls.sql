-- Tenant isolation, defence in depth. The app layer already filters by tenant; these
-- policies make a missed filter fail closed. Request scope is set per transaction:
--   app.tenant_ids  comma-separated tenant uuids the caller may touch
--   app.grant_ids   direct role grants only (not the expanded child list)
--   app.platform    'on' for Yuma IT platform staff (platform-owned rows)
-- A partner customer is not visible merely because its id was placed in app.tenant_ids.
-- The caller needs a direct grant, an active consent from a granted partner, or platform scope.

CREATE OR REPLACE FUNCTION app_tenant_ids() RETURNS uuid[]
LANGUAGE sql STABLE AS $$
  SELECT coalesce(
    string_to_array(nullif(current_setting('app.tenant_ids', true), ''), ',')::uuid[],
    '{}'::uuid[]
  )
$$;

CREATE OR REPLACE FUNCTION app_grant_ids() RETURNS uuid[]
LANGUAGE sql STABLE AS $$
  SELECT coalesce(
    string_to_array(nullif(current_setting('app.grant_ids', true), ''), ',')::uuid[],
    '{}'::uuid[]
  )
$$;

CREATE OR REPLACE FUNCTION app_is_platform() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT coalesce(current_setting('app.platform', true), '') = 'on'
$$;

-- Security definer so the check can see parent links the caller is not allowed to read.
-- Owner is the migration role (superuser) and bypasses RLS. search_path is pinned.
CREATE OR REPLACE FUNCTION app_is_partner(row_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM tenants t WHERE t.id = row_id AND t.kind = 'partner')
$$;

CREATE OR REPLACE FUNCTION app_partner_customer(row_tenant uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM tenants t
    JOIN tenants p ON p.id = t.parent_id AND p.kind = 'partner'
    WHERE t.id = row_tenant
  )
$$;

CREATE OR REPLACE FUNCTION app_partner_consented(row_tenant uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM tenants t
    JOIN partner_consents c
      ON c.customer_tenant_id = t.id
     AND c.partner_tenant_id = t.parent_id
     AND c.revoked_at IS NULL
    WHERE t.id = row_tenant
      AND t.parent_id = ANY (app_grant_ids())
  )
$$;

-- Grafana and other read-only tools log in as their own role. The mapping is
-- session_user: inside a security definer function current_user is the owner.
-- A dash_ login never consults the settable app.tenant_ids GUC.
CREATE TABLE IF NOT EXISTS dashboard_readers (
  role_name text PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);
REVOKE ALL ON TABLE dashboard_readers FROM PUBLIC;
REVOKE ALL ON TABLE dashboard_readers FROM blaksoc_app;

CREATE OR REPLACE FUNCTION app_reader_tenant() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT tenant_id FROM dashboard_readers WHERE role_name = session_user
$$;

CREATE OR REPLACE FUNCTION app_can_touch(row_tenant uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN left(session_user, 5) = 'dash_' THEN row_tenant = app_reader_tenant()
    ELSE
      row_tenant = ANY (app_grant_ids())
      OR (
        row_tenant = ANY (app_tenant_ids())
        AND (app_is_platform() OR NOT app_partner_customer(row_tenant))
      )
      OR app_partner_consented(row_tenant)
  END
$$;

CREATE OR REPLACE FUNCTION app_can_see_tenant(row_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT
    app_is_platform()
    OR row_id = ANY (app_grant_ids())
    OR (
      row_id = ANY (app_tenant_ids())
      AND EXISTS (
        SELECT 1 FROM tenants t
        WHERE t.id = row_id
          AND t.kind IS DISTINCT FROM 'partner'
          AND (t.parent_id IS NULL OR NOT app_is_partner(t.parent_id))
      )
    )
    OR EXISTS (
      SELECT 1 FROM tenants t
      JOIN partner_consents c
        ON c.customer_tenant_id = t.id
       AND c.partner_tenant_id = t.parent_id
       AND c.revoked_at IS NULL
      WHERE t.id = row_id
        AND t.parent_id = ANY (app_grant_ids())
    )
$$;

REVOKE ALL ON FUNCTION app_is_partner(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_partner_customer(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_partner_consented(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_can_touch(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_can_see_tenant(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_reader_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_is_partner(uuid) TO blaksoc_app;
GRANT EXECUTE ON FUNCTION app_partner_customer(uuid) TO blaksoc_app;
GRANT EXECUTE ON FUNCTION app_partner_consented(uuid) TO blaksoc_app;
GRANT EXECUTE ON FUNCTION app_can_touch(uuid) TO blaksoc_app;
GRANT EXECUTE ON FUNCTION app_can_see_tenant(uuid) TO blaksoc_app;
GRANT EXECUTE ON FUNCTION app_reader_tenant() TO blaksoc_app;

DO $$
DECLARE
  t text;
  strict_tables text[] := ARRAY[
    'sites','integration_tenant_links','assets','asset_sources','incidents','alerts','observables',
    'alert_observables','intel_matches','incident_alerts','incident_links','incident_timeline',
    'incident_notes','incident_tasks','evidence','vulnerabilities','detection_deployments',
    'playbook_runs','playbook_run_steps','approvals','response_actions','ai_conversations',
    'ai_messages','ai_invocations','reports','tenant_feed_entitlements','tenant_plans','usage_daily',
    'escalation_policies','notification_deliveries','e8_assessments','e8_tasks','obligation_cases','obligation_drafts',
    'monitored_domains','email_posture_checks','dmarc_reports','credential_exposures',
    'enrolment_tokens','coverage_tasks','health_baselines','board_briefs',
    'syslog_sources','syslog_events','syslog_archive',
    'dfir_collections','dfir_hunts',
    'partner_escalations',
    'backup_status',
    'training_attempts',
    'training_cosigns',
    'ir_plans',
    'ir_exercises'
  ];
  -- tenant_id NULL means a global/platform row.
  shared_tables text[] := ARRAY['sigma_rules','sigma_rule_versions','sigma_rule_tests','playbooks'];
BEGIN
  FOREACH t IN ARRAY strict_tables LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (app_can_touch(tenant_id)) WITH CHECK (app_can_touch(tenant_id))', t);
  END LOOP;

  FOREACH t IN ARRAY shared_tables LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('DROP POLICY IF EXISTS global_read ON %I', t);
    EXECUTE format('DROP POLICY IF EXISTS global_write ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (app_can_touch(tenant_id)) WITH CHECK (app_can_touch(tenant_id))', t);
    EXECUTE format('CREATE POLICY global_read ON %I FOR SELECT USING (tenant_id IS NULL)', t);
    EXECUTE format(
      'CREATE POLICY global_write ON %I USING (tenant_id IS NULL AND app_is_platform()) WITH CHECK (tenant_id IS NULL AND app_is_platform())', t);
  END LOOP;
END $$;

-- Platform-owned integrations (tenant_id NULL) are visible only to platform staff.
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON integrations;
CREATE POLICY tenant_isolation ON integrations
  USING ((tenant_id IS NULL AND app_is_platform()) OR (tenant_id IS NOT NULL AND app_can_touch(tenant_id)))
  WITH CHECK ((tenant_id IS NULL AND app_is_platform()) OR (tenant_id IS NOT NULL AND app_can_touch(tenant_id)));

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenants;
DROP POLICY IF EXISTS platform_write ON tenants;
DROP POLICY IF EXISTS tenant_insert ON tenants;
DROP POLICY IF EXISTS tenant_partner_update ON tenants;
CREATE POLICY tenant_isolation ON tenants FOR SELECT USING (app_can_see_tenant(id));
CREATE POLICY platform_write ON tenants USING (app_is_platform()) WITH CHECK (app_is_platform());
CREATE POLICY tenant_insert ON tenants FOR INSERT
  WITH CHECK (kind = 'customer' AND parent_id IS NOT NULL AND parent_id = ANY (app_grant_ids()) AND app_is_partner(parent_id));
CREATE POLICY tenant_partner_update ON tenants FOR UPDATE
  USING (app_is_partner(id) AND id = ANY (app_grant_ids()))
  WITH CHECK (app_is_partner(id) AND id = ANY (app_grant_ids()));

ALTER TABLE partner_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE partner_consents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS partner_consents_read ON partner_consents;
DROP POLICY IF EXISTS partner_consents_write ON partner_consents;
CREATE POLICY partner_consents_read ON partner_consents FOR SELECT
  USING (
    app_is_platform()
    OR partner_tenant_id = ANY (app_grant_ids())
    OR customer_tenant_id = ANY (app_grant_ids())
  );
CREATE POLICY partner_consents_write ON partner_consents FOR ALL
  USING (
    app_is_platform()
    OR partner_tenant_id = ANY (app_grant_ids())
    OR customer_tenant_id = ANY (app_grant_ids())
  )
  WITH CHECK (
    app_is_platform()
    OR partner_tenant_id = ANY (app_grant_ids())
  );

-- Audit: tenant rows readable within scope; platform rows (tenant_id NULL) to platform staff.
-- Not FORCEd: the SECURITY DEFINER chain trigger (owner) must see the true last row.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_read ON audit_log;
DROP POLICY IF EXISTS audit_insert ON audit_log;
CREATE POLICY audit_read ON audit_log FOR SELECT
  USING ((tenant_id IS NULL AND app_is_platform()) OR (tenant_id IS NOT NULL AND app_can_touch(tenant_id)));
CREATE POLICY audit_insert ON audit_log FOR INSERT
  WITH CHECK (tenant_id IS NULL OR app_can_touch(tenant_id));

-- Drafts exist before a tenant, so tenant_id is often null. A tenant_id policy would hide
-- those rows and block inserts. No permissive policy: the app role sees nothing.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['onboarding_drafts'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
  END LOOP;
END $$;

-- Login role for one customer. Name is dash_ plus the tenant uuid without hyphens.
-- NOBYPASSRLS, and app_can_touch ignores GUCs for that login. Password is not stored here.
CREATE OR REPLACE PROCEDURE provision_dashboard_reader(p_tenant uuid, p_password text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_role text;
BEGIN
  IF p_password IS NULL OR length(p_password) < 16 THEN
    RAISE EXCEPTION 'dashboard reader password is too short';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_tenant AND kind = 'customer') THEN
    RAISE EXCEPTION 'dashboard reader is for a customer tenant';
  END IF;
  v_role := 'dash_' || replace(p_tenant::text, '-', '');
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role) THEN
    EXECUTE format(
      'CREATE ROLE %I LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD %L',
      v_role, p_password
    );
  ELSE
    EXECUTE format(
      'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD %L',
      v_role, p_password
    );
  END IF;
  EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', v_role);
  EXECUTE format('GRANT SELECT ON alerts, assets, incidents TO %I', v_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION app_can_touch(uuid), app_reader_tenant(), app_tenant_ids(), app_grant_ids(), app_is_platform(), app_is_partner(uuid), app_partner_customer(uuid), app_partner_consented(uuid) TO %I',
    v_role
  );
  INSERT INTO dashboard_readers (role_name, tenant_id)
  VALUES (v_role, p_tenant)
  ON CONFLICT (role_name) DO UPDATE SET tenant_id = EXCLUDED.tenant_id;
END;
$$;

REVOKE ALL ON PROCEDURE provision_dashboard_reader(uuid, text) FROM PUBLIC;
