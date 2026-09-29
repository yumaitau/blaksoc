import { describe, expect, it } from "vitest";
import { extractAdvisoryTechniques, splitTechniqueCoverage } from "@/lib/detections/advisory-coverage";
import { BENIGN_BASELINE, measureFalsePositives, SME_DETECTIONS, smeImportPlan } from "@/lib/detections/sme-pack";
import { smeEndpointProfile } from "@/lib/detections/sme-endpoint";
import { attackTechniques, parseSigma, runTests } from "@/lib/detections/sigma";
import { advisoryFields } from "@/worker/jobs/intel";

describe("SME detection pack", () => {
  it("runs each rule through the sigma engine and measures the benign baseline", () => {
    expect(SME_DETECTIONS.length).toBeGreaterThanOrEqual(40);
    expect(BENIGN_BASELINE.length).toBeGreaterThanOrEqual(10);
    const techniques = new Set<string>();
    for (const item of SME_DETECTIONS) {
      expect(item.cases.some((c) => c.expect)).toBe(true);
      expect(item.cases.some((c) => !c.expect)).toBe(true);
      const rule = parseSigma(item.yaml);
      for (const id of attackTechniques(rule)) techniques.add(id);
      const ran = runTests(rule, item.cases);
      expect(ran.passed, rule.title).toBe(true);
    }
    for (const id of ["T1219", "T1490", "T1003.001", "T1003", "T1486", "T1105"]) expect(techniques.has(id)).toBe(true);

    const noise = measureFalsePositives();
    expect(noise.comparisons).toBe(SME_DETECTIONS.length * BENIGN_BASELINE.length);
    expect(noise.rate).toBe(0);
    expect(noise.perRule.every((row) => row.enable)).toBe(true);

    const noisy = measureFalsePositives([
      {
        yaml: `title: Any notepad
id: b27a0001-4c1d-4f8b-9a2e-0000000000ff
status: experimental
description: Matches every notepad. Used to prove the enable gate.
author: Yuma IT blakSOC
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\\notepad.exe'
  condition: selection
level: low
tags:
  - attack.execution
  - attack.t1204
`,
        cases: [
          { name: "hit", event: { Image: "C:\\Windows\\System32\\notepad.exe" }, expect: true },
          { name: "miss", event: { Image: "C:\\Windows\\System32\\cmd.exe" }, expect: false },
        ],
      },
    ]);
    expect(noisy.perRule[0]!.falsePositives).toBeGreaterThan(0);
    expect(noisy.perRule[0]!.enable).toBe(false);
    expect(noisy.rate).toBeGreaterThan(0);
  });

  it("ships a low-noise Sysmon filter and a Wazuh agent config", () => {
    const profile = smeEndpointProfile();
    expect(profile.sysmon).toContain("lsass.exe");
    expect(profile.sysmon).toContain("AnyDesk.exe");
    expect(profile.sysmon).not.toContain("<ImageLoad");
    expect(profile.wazuh).toContain("Microsoft-Windows-Sysmon/Operational");
    expect(profile.wazuh).toContain("eventchannel");
    expect(profile.wazuh.toLowerCase()).not.toContain(".msi");
    expect(profile.wazuh).not.toContain("http");
  });

  it("maps an advisory onto covered and uncovered techniques", () => {
    const text = "ACSC advisory: actors used AnyDesk and exploited FortiGate. T1190.";
    const fields = advisoryFields("acsc-advisories", "ACSC advisory", text);
    expect(fields.tags).toContain("AUSTRALIA");
    expect(fields.attackTechniques).toEqual(expect.arrayContaining(["T1219", "T1190"]));
    const named = extractAdvisoryTechniques(text);
    const have = smeImportPlan().filter((row) => row.enabled).flatMap((row) => row.attackTechniques);
    const split = splitTechniqueCoverage(named, have);
    expect(split.covered).toContain("T1219");
    expect(split.uncovered).toContain("T1190");
  });
});
