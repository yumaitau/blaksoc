import { describe, expect, it } from "vitest";
import { minSeverityFor } from "@/worker/jobs/ingest";

const row = (provider: string, config: Record<string, unknown> = {}) => ({ provider, config }) as never;

describe("ingest severity floor", () => {
  it("keeps Wazuh informational events out of blakSOC by default", () => {
    expect(minSeverityFor(row("wazuh"))).toBe("low");
  });
  it("lets an integration choose its own floor", () => {
    expect(minSeverityFor(row("wazuh", { minSeverity: "informational" }))).toBe("informational");
    expect(minSeverityFor(row("wazuh", { minSeverity: "medium" }))).toBe("medium");
    expect(minSeverityFor(row("wazuh", { minSeverity: "nonsense" }))).toBe("low");
  });
  it("stores everything from providers without a default", () => {
    expect(minSeverityFor(row("tawny"))).toBe("informational");
  });
});
