import { describe, expect, it } from "vitest";
import { artifactBody, artifactDigest, assertFixtureMode, huntMatch, renderCustody } from "@/lib/dfir/fixture";
import { LOW_BANDWIDTH_HOSTS } from "@/lib/dfir/sets";
import { sha256 } from "@/lib/crypto";

const asset = { id: "asset-1", hostname: "shared-ioc", name: "Front desk", ips: ["203.0.113.10"] };

describe("velociraptor fixture", () => {
  it("hashes the fixture body and writes that digest into the custody text", () => {
    const body = artifactBody("triage", asset);
    expect(body).toContain("artifact=triage");
    expect(body).toContain("client=shared-ioc");
    expect(artifactDigest("triage", asset)).toBe(sha256(body));
    const text = renderCustody(12, [{
      name: "Triage · shared-ioc",
      kind: "velociraptor_triage",
      sha256: artifactDigest("triage", asset),
      collectedBy: "Case Lead",
      collectedAt: new Date("2026-06-01T00:00:00.000Z"),
      storageUri: "fixture://velociraptor/c/asset-1/triage",
    }]);
    expect(text).toContain("Incident 12");
    expect(text).toContain(artifactDigest("triage", asset));
    expect(text).toContain("by Case Lead");
    expect(text).toContain("at 2026-06-01T00:00:00.000Z");
  });

  it("matches an indicator on the host and refuses live mode", () => {
    expect(huntMatch(asset, "Shared-IOC")).toBe(true);
    expect(huntMatch(asset, "203.0.113.10")).toBe(true);
    expect(huntMatch({ ...asset, hostname: "other", ips: [] }, "shared-ioc")).toBe(false);
    expect(huntMatch(asset, "  ")).toBe(false);
    expect(() => assertFixtureMode("live")).toThrow(/live Velociraptor/);
    expect(() => assertFixtureMode("fixture")).not.toThrow();
    expect(LOW_BANDWIDTH_HOSTS).toBe(3);
  });
});
