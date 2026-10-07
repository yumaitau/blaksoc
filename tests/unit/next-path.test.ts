import { describe, expect, it } from "vitest";
import { safeNextPath } from "@/lib/auth/next-path";

describe("safeNextPath", () => {
  it("keeps same-origin paths with query and hash", () => {
    expect(safeNextPath("/soc/incidents/1?tab=notes#n2")).toBe("/soc/incidents/1?tab=notes#n2");
  });

  it("refuses anything a browser would send off-site", () => {
    for (const next of [undefined, "", "soc", "//evil.example", "/\\evil.example", "/\t/evil.example", "/\n/evil.example", "https://evil.example", "/%2F%2Fevil.example/../"]) {
      const out = safeNextPath(next);
      expect(new URL(out, "https://soc.example").origin, String(next)).toBe("https://soc.example");
    }
    expect(safeNextPath("/\\evil.example")).toBe("/");
  });
});
