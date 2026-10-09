-- Office displays retain a fixed customer scope and stop when their issuer loses access.
CREATE TABLE IF NOT EXISTS "wallboard_links" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "name" text NOT NULL,
  "tenant_ids" uuid[] NOT NULL,
  "created_by" text NOT NULL REFERENCES "user"("id") ON DELETE cascade,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "revoked_at" timestamp with time zone,
  CONSTRAINT "wallboard_links_scope" CHECK (cardinality("tenant_ids") > 0),
  CONSTRAINT "wallboard_links_name" CHECK (length("name") between 1 and 80),
  CONSTRAINT "wallboard_links_expiry" CHECK ("expires_at" > "created_at")
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "wallboard_links_created_by" ON "wallboard_links" ("created_by");
