import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const journal = JSON.parse(readFileSync("drizzle/meta/_journal.json", "utf8")) as { entries: { idx: number; when: number; tag: string }[] };

describe("migration journal", () => {
  // The migrator applies only entries newer than the last applied `when`; an out-of-order one is skipped silently.
  it("has strictly increasing timestamps in index order", () => {
    const entries = [...journal.entries].sort((a, b) => a.idx - b.idx);
    for (let i = 1; i < entries.length; i++) expect(entries[i]!.when, entries[i]!.tag).toBeGreaterThan(entries[i - 1]!.when);
  });

  it("lists every SQL file once, tagged with its own index", () => {
    const files = readdirSync("drizzle").filter((f) => /^\d{4}_.*\.sql$/.test(f)).map((f) => f.slice(0, -4)).sort();
    expect(journal.entries.map((e) => e.tag).sort()).toEqual(files);
    for (const e of journal.entries) expect(Number(e.tag.slice(0, 4)), e.tag).toBe(e.idx);
  });
});
