import { describe, expect, it } from "vitest";
import { DEFAULT_TENANT_SETTINGS, MOST_PROTECTIVE, type GovernanceProfile } from "@/db/schema";
import { approvalsRequired, checkGovernedAi, checkGovernedRegion, checkGovernedSighting, describeProfile, diffProfile } from "@/lib/governance/policy";
import { parseEpssCsv } from "@/worker/jobs/intel";

const provider = (country: string) => ({ id: `p-${country}`, residency: { region: country === "AU" ? "ap-southeast-2" : "us-east-1", country, selfHosted: false } });
const open: GovernanceProfile = { residencyLock: false, sightings: null, ai: { assistant: true, triage_summary: true } };
const consent = { attribution: "anonymised" as const, maxTlp: "TLP:GREEN" as const, consentedBy: ["s1"], consentedAt: "2026-10-06T00:00:00Z" };

describe("data governance policy", () => {
  it("defaults to the most protective profile", () => {
    expect(MOST_PROTECTIVE).toEqual({ residencyLock: true, sightings: null, ai: { assistant: false, triage_summary: false } });
  });

  it("refuses AI unless stewards turned the capability on", () => {
    expect(checkGovernedAi(MOST_PROTECTIVE, "assistant", provider("AU")).allowed).toBe(false);
    expect(checkGovernedAi({ ...open, ai: { assistant: true, triage_summary: false } }, "triage_summary", provider("AU")).allowed).toBe(false);
    expect(checkGovernedAi(open, "assistant", provider("AU")).allowed).toBe(true);
  });

  it("refuses a non-AU AI provider under the residency lock", () => {
    const decision = checkGovernedAi({ ...open, residencyLock: true }, "assistant", provider("US"));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain("residency lock");
    expect(checkGovernedAi(open, "assistant", provider("US")).allowed).toBe(true);
  });

  it("refuses intel regions outside Australia under the lock", () => {
    expect(checkGovernedRegion(MOST_PROTECTIVE, "us-east-1").allowed).toBe(false);
    expect(checkGovernedRegion(MOST_PROTECTIVE, "ap-southeast-4").allowed).toBe(true);
    expect(checkGovernedRegion(MOST_PROTECTIVE, undefined).allowed).toBe(true);
    expect(checkGovernedRegion(open, "us-east-1").allowed).toBe(true);
  });

  it("refuses a sighting without steward consent even when the tenant setting allows it", () => {
    const sharing = { createSightings: true, attribution: "anonymised" as const, maxTlp: "TLP:AMBER" as const };
    const refused = checkGovernedSighting(MOST_PROTECTIVE, sharing);
    expect(refused.allowed).toBe(false);
    expect(checkGovernedSighting({ ...open, sightings: consent }, DEFAULT_TENANT_SETTINGS.sharing).allowed).toBe(false);
  });

  it("applies the narrower of setting and consent", () => {
    const named = { createSightings: true, attribution: "named" as const, maxTlp: "TLP:AMBER" as const };
    expect(checkGovernedSighting({ ...open, sightings: consent }, named)).toEqual({ allowed: true, attribution: "anonymised", maxTlp: "TLP:GREEN" });
    const wide = { ...consent, attribution: "named" as const, maxTlp: "TLP:RED" as const };
    expect(checkGovernedSighting({ ...open, sightings: wide }, named)).toEqual({ allowed: true, attribution: "named", maxTlp: "TLP:AMBER" });
  });

  it("needs two approvals once there are two stewards", () => {
    expect(approvalsRequired(0)).toBe(1);
    expect(approvalsRequired(1)).toBe(1);
    expect(approvalsRequired(2)).toBe(2);
    expect(approvalsRequired(5)).toBe(2);
  });

  it("describes the profile in plain language and diffs changes", () => {
    expect(describeProfile(MOST_PROTECTIVE).join(" ")).toContain("Your data stays in Australia.");
    expect(describeProfile(MOST_PROTECTIVE).join(" ")).toContain("AI is off for your data.");
    expect(diffProfile(MOST_PROTECTIVE, { ...MOST_PROTECTIVE, sightings: consent, ai: { assistant: true, triage_summary: false } }))
      .toEqual(["sightings none to anonymised up to TLP:GREEN", "AI assistant on"]);
  });

  it("reads only wanted rows from the EPSS bulk file", () => {
    const csv = "#model_version:v2025,score_date:2026-10-05\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\nCVE-2024-0002,0.1,0.2\n";
    const out = parseEpssCsv(csv, new Set(["CVE-2024-0002"]));
    expect([...out.entries()]).toEqual([["CVE-2024-0002", { epss: 0.1, percentile: 0.2 }]]);
  });
});
