-- Entity graph (src/lib/graph). Postgres tables with RLS, so tenant isolation stays in one mechanism.
-- Composite (id, tenant_id) foreign keys stop an alias or edge pointing at another tenant's entity.
DO $$ BEGIN
  CREATE TYPE "entity_type" AS ENUM ('user', 'identity', 'device', 'ip', 'domain', 'url', 'file', 'process', 'cloud_resource', 'indicator', 'threat_actor', 'campaign', 'email', 'alert');
EXCEPTION WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
  CREATE TYPE "relationship_provenance" AS ENUM ('observed', 'inferred');
EXCEPTION WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "entities" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "type" "entity_type" NOT NULL,
  "key" text NOT NULL,
  "display_name" text NOT NULL,
  "identifiers" jsonb DEFAULT '{}'::jsonb NOT NULL,
  "source_systems" text[] DEFAULT '{}' NOT NULL,
  "first_seen" timestamp with time zone DEFAULT now() NOT NULL,
  "last_seen" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "entities_id_tenant" UNIQUE ("id", "tenant_id")
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "entities_key" ON "entities" ("tenant_id", "type", "key");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "entity_aliases" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "entity_id" uuid NOT NULL,
  "kind" text NOT NULL,
  "value" text NOT NULL,
  "source" text NOT NULL,
  "first_seen" timestamp with time zone DEFAULT now() NOT NULL,
  "last_seen" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "entity_aliases_entity_fk" FOREIGN KEY ("entity_id", "tenant_id") REFERENCES "entities"("id", "tenant_id") ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "entity_aliases_value" ON "entity_aliases" ("tenant_id", "kind", "value");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "entity_aliases_entity" ON "entity_aliases" ("entity_id");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "entity_relationships" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "from_entity_id" uuid NOT NULL,
  "to_entity_id" uuid NOT NULL,
  "type" text NOT NULL,
  "provenance" "relationship_provenance" NOT NULL,
  "count" integer DEFAULT 0 NOT NULL,
  "first_seen" timestamp with time zone DEFAULT now() NOT NULL,
  "last_seen" timestamp with time zone DEFAULT now() NOT NULL,
  "evidence_type" text NOT NULL,
  "evidence_id" text NOT NULL,
  CONSTRAINT "entity_relationships_from_fk" FOREIGN KEY ("from_entity_id", "tenant_id") REFERENCES "entities"("id", "tenant_id") ON DELETE cascade,
  CONSTRAINT "entity_relationships_to_fk" FOREIGN KEY ("to_entity_id", "tenant_id") REFERENCES "entities"("id", "tenant_id") ON DELETE cascade,
  CONSTRAINT "entity_relationships_no_loop" CHECK ("from_entity_id" <> "to_entity_id")
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "entity_relationships_unique" ON "entity_relationships" ("tenant_id", "from_entity_id", "to_entity_id", "type");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "entity_relationships_from" ON "entity_relationships" ("from_entity_id", "type");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "entity_relationships_to" ON "entity_relationships" ("to_entity_id", "type");
--> statement-breakpoint
-- Every record that asserted an edge. The primary key makes re-ingest and backfill idempotent:
-- an edge's count only moves when a new piece of evidence lands here.
CREATE TABLE IF NOT EXISTS "entity_relationship_evidence" (
  "relationship_id" uuid NOT NULL REFERENCES "entity_relationships"("id") ON DELETE cascade,
  "tenant_id" uuid NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "evidence_type" text NOT NULL,
  "evidence_id" text NOT NULL,
  "observed_at" timestamp with time zone NOT NULL,
  CONSTRAINT "entity_relationship_evidence_pk" PRIMARY KEY ("relationship_id", "evidence_type", "evidence_id")
);
