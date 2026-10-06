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

  it("rejects the wrong role", () => {
    expect(urlPasswordMismatch("DATABASE_URL", "postgres://blaksoc:x@db/blaksoc", "blaksoc_app", "x")).toMatch(/blaksoc_app/);
  });
});
