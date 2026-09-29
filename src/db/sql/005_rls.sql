-- Tenant isolation, defence in depth. The app layer already filters by tenant; these
-- policies make a missed filter fail closed. Request scope is set per transaction:
--   app.tenant_ids  comma-separated tenant uuids the caller may touch
--   app.platform    'on' for Yuma IT platform staff (platform-owned rows)

CREATE OR REPLACE FUNCTION app_tenant_ids() RETURNS uuid[]
LANGUAGE sql STABLE AS $$
  SELECT coalesce(
    string_to_array(nullif(current_setting('app.tenant_ids', true), ''), ',')::uuid[],
    '{}'::uuid[]
  )
$$;

CREATE OR REPLACE FUNCTION app_is_platform() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT coalesce(current_setting('app.platform', true), '') = 'on'
$$;

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
    'syslog_sources','syslog_events','syslog_archive'
  ];
  -- tenant_id NULL means a global/platform row.
  shared_tables text[] := ARRAY['sigma_rules','sigma_rule_versions','sigma_rule_tests','playbooks'];
BEGIN
  FOREACH t IN ARRAY strict_tables LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = ANY (app_tenant_ids())) WITH CHECK (tenant_id = ANY (app_tenant_ids()))', t);
  END LOOP;

  FOREACH t IN ARRAY shared_tables LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('DROP POLICY IF EXISTS global_read ON %I', t);
    EXECUTE format('DROP POLICY IF EXISTS global_write ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = ANY (app_tenant_ids())) WITH CHECK (tenant_id = ANY (app_tenant_ids()))', t);
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
  USING (tenant_id = ANY (app_tenant_ids()) OR (tenant_id IS NULL AND app_is_platform()))
  WITH CHECK (tenant_id = ANY (app_tenant_ids()) OR (tenant_id IS NULL AND app_is_platform()));

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenants;
DROP POLICY IF EXISTS platform_write ON tenants;
CREATE POLICY tenant_isolation ON tenants FOR SELECT USING (id = ANY (app_tenant_ids()) OR app_is_platform());
CREATE POLICY platform_write ON tenants USING (app_is_platform()) WITH CHECK (app_is_platform());

-- Audit: tenant rows readable within scope; platform rows (tenant_id NULL) to platform staff.
-- Not FORCEd: the SECURITY DEFINER chain trigger (owner) must see the true last row.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_read ON audit_log;
DROP POLICY IF EXISTS audit_insert ON audit_log;
CREATE POLICY audit_read ON audit_log FOR SELECT
  USING (tenant_id = ANY (app_tenant_ids()) OR (tenant_id IS NULL AND app_is_platform()));
CREATE POLICY audit_insert ON audit_log FOR INSERT
  WITH CHECK (tenant_id IS NULL OR tenant_id = ANY (app_tenant_ids()));

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
