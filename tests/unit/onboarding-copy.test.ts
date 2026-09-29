import { describe, expect, it } from "vitest";
import { lookupAbn } from "@/lib/onboarding/abn";
import { allCopyText, readingAge } from "@/lib/onboarding/copy";

describe("onboarding copy", () => {
  it("reads at age 12 or under, and a hard sentence scores higher", () => {
    expect(readingAge(allCopyText())).toBeLessThanOrEqual(12);
    expect(readingAge("The comprehensive organisational cybersecurity infrastructure necessitates multifaceted administrative authentication procedures.")).toBeGreaterThan(12);
  });

  it("checks the example ABN list and does not invent other matches", () => {
    expect(lookupAbn("51 824 753 556")).toMatchObject({ abn: "51824753556", found: true, name: "Example Business" });
    expect(lookupAbn("12345678901").found).toBe(false);
  });
});
