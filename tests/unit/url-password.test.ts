import { describe, expect, it } from "vitest";
import { urlPasswordMismatch } from "@/db/url-password";

describe("database URL password check", () => {
  it("accepts a URL whose password matches the role password", () => {
    expect(urlPasswordMismatch("DATABASE_SYSTEM_URL", "postgres://blaksoc_system:abc123@db:5432/blaksoc", "blaksoc_system", "abc123")).toBeNull();
    const pw = "p#ss/w@rd?%";
    expect(urlPasswordMismatch("DATABASE_SYSTEM_URL", `postgres://blaksoc_system:${encodeURIComponent(pw)}@db:5432/blaksoc`, "blaksoc_system", pw)).toBeNull();
  });

  it("rejects a raw password that URL parsing would cut short", () => {
    expect(urlPasswordMismatch("DATABASE_SYSTEM_URL", "postgres://blaksoc_system:p#ss@db:5432/blaksoc", "blaksoc_system", "p#ss")).toMatch(/percent-encode/);
  });

  it("accepts what postgres.js accepts: multiple hosts, and user or password left to PGUSER/PGPASSWORD", () => {
    expect(urlPasswordMismatch("DATABASE_URL", "postgres://blaksoc_app:pw@h1:5432,h2:5432/blaksoc", "blaksoc_app", "pw")).toBeNull();
    expect(urlPasswordMismatch("DATABASE_URL", "postgres://blaksoc_app@db/blaksoc", "blaksoc_app", "pw")).toBeNull();
    expect(urlPasswordMismatch("DATABASE_URL", "postgres://db/blaksoc", "blaksoc_app", "pw")).toBeNull();
  });

  it("returns a message, not a thrown error, for a malformed escape", () => {
    expect(urlPasswordMismatch("DATABASE_URL", "postgres://blak%E0:pw@db/blaksoc", "blaksoc_app", "pw")).toMatch(/not a valid connection URL/);
    expect(urlPasswordMismatch("DATABASE_URL", "postgres://blaksoc_app:p%E0@db/blaksoc", "blaksoc_app", "pw")).toMatch(/not a valid connection URL/);
  });

  it("rejects the wrong role", () => {
    expect(urlPasswordMismatch("DATABASE_URL", "postgres://blaksoc:x@db/blaksoc", "blaksoc_app", "x")).toMatch(/blaksoc_app/);
  });
});
