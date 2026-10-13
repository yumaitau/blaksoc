-- ISM controls and Essential Eight strategies a detector (Wedgetail) mapped an alert to, as first-class
-- columns so the queue can filter and the compliance view can count them. Earlier Wedgetail alerts kept
-- them only in raw; backfill normalises those (see src/lib/compliance/refs.ts for the same mapping).
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "ism_controls" text[] DEFAULT '{}' NOT NULL;
--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "e8_strategies" text[] DEFAULT '{}' NOT NULL;
--> statement-breakpoint
UPDATE "alerts" a SET
  "ism_controls" = coalesce((
    SELECT array_agg(DISTINCT upper(r) ORDER BY upper(r)) FROM jsonb_array_elements_text(a."raw"->'ism') r WHERE r ~* '^ISM-[0-9]{4}$'
  ), '{}'),
  "e8_strategies" = coalesce((
    SELECT array_agg(DISTINCT m.id) FROM jsonb_array_elements_text(a."raw"->'essentialEight') r
    JOIN (VALUES
      ('application_control', 'application_control'), ('patch_applications', 'patch_applications'),
      ('office_macros', 'office_macros'), ('restrict_microsoft_office_macros', 'office_macros'),
      ('configure_microsoft_office_macro_settings', 'office_macros'),
      ('user_application_hardening', 'user_app_hardening'), ('user_app_hardening', 'user_app_hardening'),
      ('restrict_admin_privileges', 'restrict_admin'), ('restrict_administrative_privileges', 'restrict_admin'), ('restrict_admin', 'restrict_admin'),
      ('patch_operating_systems', 'patch_os'), ('patch_os', 'patch_os'),
      ('multi_factor_authentication', 'mfa'), ('mfa', 'mfa'), ('regular_backups', 'regular_backups')
    ) AS m(alias, id) ON m.alias = regexp_replace(regexp_replace(lower(trim(r)), ':ml[0-3]$', ''), '[\s-]+', '_', 'g')
  ), '{}')
WHERE a."source" = 'wedgetail' AND (jsonb_typeof(a."raw"->'ism') = 'array' OR jsonb_typeof(a."raw"->'essentialEight') = 'array');
