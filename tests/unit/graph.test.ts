import { describe, expect, it } from "vitest";
import type { IntelMatch } from "@/db/schema";
import { accountCandidates, alertFacts, assetFacts, canonicalKey, loginOutcome, observableEntity, type AlertGraphInput } from "@/lib/graph/model";

const match: IntelMatch = {
  observable: { type: "ipv4", value: "185.220.101.47" }, openctiId: "indicator--1", entityType: "Indicator", verdict: "malicious", score: 85, confidence: 80,
  source: "AlienVault OTX", markings: [], labels: [], firstSeen: null, lastSeen: null, threatActors: ["Actor X"], intrusionSets: [], malware: [],
  campaigns: ["Spray 2026"], attackPatterns: [], relatedIndicators: [], sightings: 1,
};

const base: AlertGraphInput = {
  alert: { id: "a1", title: "Successful logon from external IP", source: "wazuh", externalId: "x1", severity: "high", category: "windows", occurredAt: new Date("2026-10-01T00:00:00Z"), userName: "Alice", raw: { rule: { groups: ["authentication_success"] } } },
  asset: { id: "asset-1", kind: "endpoint", name: "WS-01", hostname: "WS-01.corp.example" },
  hostname: "ws-01.corp.example",
  observables: [{ type: "ipv4", value: "185.220.101.47" }, { type: "hostname", value: "ws-01" }, { type: "user", value: "Alice" }, { type: "cve", value: "CVE-2024-3400" }],
  intel: [{ id: "m1", match }],
};

const edge = (f: ReturnType<typeof alertFacts>, type: string) => f.edges.filter((e) => e.type === type).map((e) => `${e.from.type}:${e.from.key}->${e.to.type}:${e.to.key}:${e.provenance}`);

describe("entity keys", () => {
  it("normalises per type so the same thing gets the same key from any record", () => {
    expect(canonicalKey("device", "WS-01.corp.example")).toBe("ws-01");
    expect(canonicalKey("user", " Alice ")).toBe("alice");
    expect(canonicalKey("url", "http://X.example/A")).toBe("http://X.example/A");
    expect(canonicalKey("url", `http://x.example/${"a".repeat(600)}`)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(observableEntity({ type: "sha256", value: "AB".repeat(32) })).toMatchObject({ type: "file", key: `sha256:${"ab".repeat(32)}` });
    expect(observableEntity({ type: "cve", value: "CVE-2024-3400" })).toBeNull();
  });

  it("lists the account names a user may appear under", () => {
    expect(accountCandidates("CORP\\JSmith")).toEqual(["corp\\jsmith", "jsmith"]);
    expect(accountCandidates("alice@corp.example")).toEqual(["alice@corp.example", "alice"]);
  });
});

describe("alert facts", () => {
  it("links the alert to its device, user, observables and intel with evidence", () => {
    const f = alertFacts({ ...base, identity: { key: "alice@corp.example" } });
    expect(edge(f, "alerted_on").sort()).toEqual(["alert:a1->device:ws-01:observed", "alert:a1->ip:185.220.101.47:observed", "alert:a1->user:alice:observed"]);
    expect(edge(f, "logged_into")).toEqual(["user:alice->device:ws-01:observed"]);
    expect(edge(f, "same_as")).toEqual(["user:alice->identity:alice@corp.example:inferred"]);
    expect(edge(f, "matched")).toEqual(["alert:a1->indicator:indicator--1:observed"]);
    expect(edge(f, "indicates")).toEqual(["indicator:indicator--1->ip:185.220.101.47:observed"]);
    expect(edge(f, "attributed_to").sort()).toEqual(["indicator:indicator--1->campaign:spray 2026:observed", "indicator:indicator--1->threat_actor:actor x:observed"]);
    expect(f.edges.find((e) => e.type === "indicates")!.evidence).toEqual({ type: "intel_match", id: "m1" });
    expect(f.edges.find((e) => e.type === "alerted_on")!.evidence).toEqual({ type: "alert", id: "a1" });
    expect(f.aliases).toContainEqual({ entity: { type: "device", key: "ws-01" }, kind: "asset_id", value: "asset-1", source: "wazuh" });
  });

  it("infers logged_into for non-authentication alerts and omits it for failed sign-ins", () => {
    const other = alertFacts({ ...base, alert: { ...base.alert, title: "Encoded PowerShell", raw: {} } });
    expect(edge(other, "logged_into")).toEqual(["user:alice->device:ws-01:inferred"]);
    const failed = alertFacts({ ...base, alert: { ...base.alert, title: "Logon failure", raw: { rule: { groups: ["authentication_failed"] } } } });
    expect(edge(failed, "logged_into")).toEqual([]);
  });

  it("reads sign-in outcome and network peers from OCSF", () => {
    expect(loginOutcome({ ...base.alert, title: "x", raw: {}, ocsfSourceEvent: { class_uid: 3002, status_id: 2 } as never })).toBe("failure");
    const f = alertFacts({ ...base, asset: null, hostname: null, alert: { ...base.alert, userName: null, ocsfSourceEvent: { class_uid: 4001, src_endpoint: { ip: "203.0.113.10" }, dst_endpoint: { ip: "10.0.0.5" } } as never } });
    expect(edge(f, "communicated_with")).toEqual(["ip:203.0.113.10->ip:10.0.0.5:observed"]);
  });
});

describe("asset facts", () => {
  it("records inventory identifiers as aliases and device IPs as edges", () => {
    const f = assetFacts({ id: "asset-1", kind: "server", name: "WEB01", hostname: "web01.corp.example", ips: ["10.0.0.5"], dedupeKeys: ["src:i1:001", "host:web01", "mac:aa:bb"] }, "wazuh");
    expect(f.entities[0]).toMatchObject({ type: "device", key: "web01", displayName: "WEB01", identifiers: { assetId: "asset-1" } });
    expect(f.aliases.map((a) => `${a.kind}=${a.value}`).sort()).toEqual(["asset_id=asset-1", "fqdn=web01.corp.example", "host=web01", "mac=aa:bb", "src=i1:001"]);
    expect(f.edges.map((e) => `${e.type}:${e.to.key}`)).toEqual(["has_ip:10.0.0.5"]);
  });

  it("matches identities to existing user entities by account name", () => {
    const f = assetFacts({ id: "id-1", kind: "identity", name: "alice@corp.example", hostname: null }, "entra", { matchingUsers: ["alice"] });
    expect(f.aliases.filter((a) => a.kind === "account").map((a) => a.value)).toEqual(["alice@corp.example", "alice"]);
    expect(f.edges).toMatchObject([{ type: "same_as", provenance: "inferred", from: { type: "user", key: "alice" }, to: { type: "identity", key: "alice@corp.example" } }]);
    // The user is linked, not updated: the identity's source and last seen are not the user's.
    expect(f.existing).toEqual([{ type: "user", key: "alice" }]);
    expect(f.entities.map((e) => e.type)).toEqual(["identity"]);
  });
});
