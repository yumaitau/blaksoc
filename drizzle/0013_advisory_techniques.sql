ALTER TABLE "advisories" ADD COLUMN IF NOT EXISTS "attack_techniques" text[] DEFAULT '{}'::text[] NOT NULL;
