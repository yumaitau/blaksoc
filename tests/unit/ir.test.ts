import { describe, expect, it } from "vitest";
import { docxBytes } from "@/lib/ir/docx";
import { IR_SCENARIOS } from "@/lib/ir/scenarios";

describe("incident response scenarios", () => {
  it("ships four tabletops, including payment fraud and ransomware", () => {
    expect(IR_SCENARIOS.map((scenario) => scenario.id)).toEqual([
      "bec-payment",
      "ransomware-remote",
      "lost-laptop",
      "cultural-leak",
    ]);
    for (const scenario of IR_SCENARIOS) {
      expect(scenario.injects.length).toBeGreaterThanOrEqual(3);
      expect(scenario.prompts.length).toBeGreaterThanOrEqual(2);
    }
  });

  it("writes a Word file that contains the plan text", () => {
    const bytes = Buffer.from(docxBytes(["River Clinic", "This plan has not been reviewed by an advisory group."]));
    expect(bytes.subarray(0, 2).toString()).toBe("PK");
    const xml = bytes.toString("utf8");
    expect(xml).toContain("River Clinic");
    expect(xml).toContain("has not been reviewed");
  });
});
