CREATE TABLE IF NOT EXISTS "board_briefs" (
  "tenant_id" uuid PRIMARY KEY REFERENCES "tenants"("id") ON DELETE cascade,
  "preamble" text,
  "image_mime" text,
  "image_data" text,
  "span" text DEFAULT 'month' NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
