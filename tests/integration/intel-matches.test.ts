import { sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db } from "@/db/client";
import { customerMatchFilter } from "@/lib/intel/match-filter";

describe("customer intel match noise filter", () => {
  it("filters generic GitHub matches before LIMIT while keeping actionable URLs and lookalikes", async () => {
    const observables = [
      { type: "domain", value: "github.com" },
      { type: "domain", value: "GITHUB.COM." },
      { type: "domain", value: " www.github.com " },
      { type: "url", value: "https://github.com/" },
      { type: "url", value: "https://www.github.com" },
      { type: "url", value: "https://github.com/actor/payload.exe" },
      { type: "domain", value: "github.com.evil.example" },
      { type: "domain", value: "evilgithub.com" },
      { type: "domain", value: "raw.githubusercontent.com" },
      { type: "url", value: "https://evil.example/github.com" },
    ];
    // Read-only VALUES query: validates the actual PostgreSQL predicate without modifying fixtures.
    const values = sql.join(observables.map((observable, i) => sql`(${i}::int, ${JSON.stringify({ observable })}::jsonb)`), sql`, `);
    const result = await db().execute(sql`with samples(id, summary) as (values ${values})
      select id from samples where ${customerMatchFilter(sql`summary`)} order by id limit 3`);
    expect(result.map((row) => row.id)).toEqual([5, 6, 7]);
    const all = await db().execute(sql`with samples(id, summary) as (values ${values})
      select id from samples where ${customerMatchFilter(sql`summary`)} order by id`);
    expect(all.map((row) => row.id)).toEqual([5, 6, 7, 8, 9]);
  });
});
