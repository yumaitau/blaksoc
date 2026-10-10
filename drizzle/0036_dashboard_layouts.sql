-- One SOC dashboard arrangement per analyst. The row is visible only to that user (see 005_rls.sql).
CREATE TABLE IF NOT EXISTS "dashboard_layouts" (
  "user_id" text PRIMARY KEY NOT NULL REFERENCES "user"("id") ON DELETE cascade,
  "widgets" jsonb NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "dashboard_layouts_widgets" CHECK (jsonb_typeof("widgets") = 'array' AND jsonb_array_length("widgets") BETWEEN 1 AND 40)
);
