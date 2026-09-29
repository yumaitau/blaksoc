import { describe, expect, it } from "vitest";
import { BUILTIN_ROLES } from "@/lib/auth/permissions";
import { DemoProvider } from "@/lib/providers/demo";
import { scenarioSchema, SCENARIOS } from "@/lib/training/scenarios";
import { scoreAttempt, TRAINING_SKILLS } from "@/lib/training/score";

describe("training scenarios", () => {
  it("ships at least ten scenarios, including BEC and ransomware", () => {
    expect(SCENARIOS.length).toBeGreaterThanOrEqual(10);
    expect(SCENARIOS.some((scenario) => scenario.id === "bec-payment" && scenario.tags.includes("bec"))).toBe(true);
    expect(SCENARIOS.some((scenario) => scenario.id === "ransomware-lock" && scenario.tags.includes("ransomware"))).toBe(true);
    for (const scenario of SCENARIOS) {
      expect(scenarioSchema.parse(scenario).id).toBe(scenario.id);
    }
  });

  it("maps skills to the L1 analyst role", () => {
    const l1 = BUILTIN_ROLES.find((role) => role.key === "soc_analyst_l1");
    expect(l1).toBeTruthy();
    for (const skill of TRAINING_SKILLS) {
      expect(l1!.permissions).toContain(skill);
    }
  });

  it("scores ordered actions and subtracts hints", () => {
    const expected = ["triage", "escalate", "note"];
    expect(scoreAttempt(expected, expected, 0)).toBe(100);
    expect(scoreAttempt(expected, ["close", "close", "close"], 0)).toBe(0);
    expect(scoreAttempt(expected, expected, 1)).toBe(90);
  });

  it("materialises a stable demo alert", () => {
    const spec = SCENARIOS.find((scenario) => scenario.id === "bec-payment")!.events[0]!;
    const provider = new DemoProvider([]);
    const agent = { id: "train-1", name: "training-pc", ip: "203.0.113.50" };
    const now = new Date("2026-07-01T00:00:00.000Z");
    const first = provider.materialise(spec, agent, "training:bec-payment:ada:0", now);
    const second = provider.materialise(spec, agent, "training:bec-payment:ada:0", now);
    expect(first.title).toBe(spec.title);
    expect(first.externalId).toBe("training:bec-payment:ada:0");
    expect(second).toEqual(first);
  });
});
