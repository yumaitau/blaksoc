-- Training tenants may keep a demo provider row. Any other provider is rejected,
-- including a direct insert that bypasses the application.
CREATE OR REPLACE FUNCTION reject_training_real_integration() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  tid uuid;
  provider text;
  training boolean;
BEGIN
  IF TG_TABLE_NAME = 'integrations' THEN
    tid := NEW.tenant_id;
    provider := NEW.provider;
  ELSE
    tid := NEW.tenant_id;
    SELECT i.provider INTO provider FROM integrations i WHERE i.id = NEW.integration_id;
  END IF;
  IF tid IS NULL OR provider = 'demo' THEN
    RETURN NEW;
  END IF;
  SELECT coalesce((settings->>'training')::boolean, false) INTO training FROM tenants WHERE id = tid;
  IF training THEN
    RAISE EXCEPTION 'training tenant cannot use a real integration';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS training_isolation_integrations ON integrations;
CREATE TRIGGER training_isolation_integrations
  BEFORE INSERT OR UPDATE ON integrations
  FOR EACH ROW EXECUTE FUNCTION reject_training_real_integration();

DROP TRIGGER IF EXISTS training_isolation_links ON integration_tenant_links;
CREATE TRIGGER training_isolation_links
  BEFORE INSERT OR UPDATE ON integration_tenant_links
  FOR EACH ROW EXECUTE FUNCTION reject_training_real_integration();
