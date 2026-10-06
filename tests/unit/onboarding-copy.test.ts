import { describe, expect, it } from "vitest";
import { lookupAbn, lookupExampleAbn, parseAbrJsonp, validAbn } from "@/lib/onboarding/abn";
import { allCopyText, readingAge } from "@/lib/onboarding/copy";

describe("onboarding copy", () => {
  it("reads at age 12 or under, and a hard sentence scores higher", () => {
    expect(readingAge(allCopyText())).toBeLessThanOrEqual(12);
    expect(readingAge("The comprehensive organisational cybersecurity infrastructure necessitates multifaceted administrative authentication procedures.")).toBeGreaterThan(12);
  });

  it("checks the example ABN list and does not invent other matches", async () => {
    expect(lookupExampleAbn("51 824 753 556")).toMatchObject({ abn: "51824753556", found: true, name: "Example Business", source: "example" });
    expect(lookupExampleAbn("12345678901").found).toBe(false);
    expect(await lookupAbn("51824753556")).toMatchObject({ found: true, source: "example" });
  });

  it("validates the ABN checksum", () => {
    expect(validAbn("51824753556")).toBe(true);
    expect(validAbn("51824753557")).toBe(false);
    expect(validAbn("1234")).toBe(false);
  });

  const reply = (body: string, ok = true) => async () => ({ ok, status: ok ? 200 : 500, text: async () => body });

  it("asks the business register when a GUID is set", async () => {
    let asked = "";
    const found = await lookupAbn("51824753556", {
      guid: "g-1",
      fetch: async (url) => {
        asked = url;
        return reply('c({"Abn":"51824753556","AbnStatus":"Active","EntityName":"RIVER CLINIC LTD","BusinessName":[],"Message":""})')();
      },
    });
    expect(asked).toContain("abn=51824753556");
    expect(asked).toContain("guid=g-1");
    expect(found).toEqual({ abn: "51824753556", found: true, name: "RIVER CLINIC LTD", source: "abr", status: "Active" });
  });

  it("separates not listed, a bad GUID, and an outage", async () => {
    const miss = await lookupAbn("51824753556", { guid: "g", fetch: reply('c({"Abn":"","Message":"Search text is not a valid ABN or ACN"})') });
    expect(miss).toMatchObject({ found: false, source: "abr" });
    const guid = await lookupAbn("51824753556", { guid: "g", fetch: reply('c({"Abn":"","Message":"The GUID entered is not recognised as a Registered Party"})') });
    expect(guid).toMatchObject({ found: false, source: "unavailable" });
    const down = await lookupAbn("51824753556", { guid: "g", fetch: reply("", false) });
    expect(down).toMatchObject({ found: false, source: "unavailable" });
    expect(() => parseAbrJsonp("<html>")).toThrow();
  });
});
