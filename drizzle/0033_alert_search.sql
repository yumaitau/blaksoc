-- Full-text search over alerts (src/lib/services/alerts.ts). The 'simple' configuration does not
-- stem or drop stop words, so host names, user names, rule ids and IOCs match as written.
-- Not declared in the Drizzle schema: the column is generated and only used in WHERE clauses.
ALTER TABLE "alerts" ADD COLUMN IF NOT EXISTS "search_vector" tsvector GENERATED ALWAYS AS (
  setweight(to_tsvector('simple', coalesce("title", '')), 'A') ||
  setweight(to_tsvector('simple', coalesce("user_name", '')), 'B') ||
  setweight(to_tsvector('simple', coalesce("category", '') || ' ' || coalesce("rule_id", '') || ' ' || coalesce("source", '')), 'C') ||
  setweight(to_tsvector('simple', coalesce("description", '')), 'D')
) STORED;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "alerts_search" ON "alerts" USING gin ("search_vector");
