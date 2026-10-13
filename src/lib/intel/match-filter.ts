import { sql, type SQLWrapper } from "drizzle-orm";

/** Exclude generic GitHub host hits, retaining specific repository/file URLs and lookalikes. */
export function customerMatchFilter(summary: SQLWrapper) {
  return sql`not coalesce(
    (${summary}->'observable'->>'type' = 'domain'
      and lower(rtrim(btrim(${summary}->'observable'->>'value'), '.')) in ('github.com', 'www.github.com'))
    or (${summary}->'observable'->>'type' = 'url'
      and ${summary}->'observable'->>'value' ~* '^https?://(www[.])?github[.]com[.]?/?$'), false)`;
}
