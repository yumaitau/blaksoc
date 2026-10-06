import { describe, expect, it } from "vitest";
import { KelpieClient, KelpieError, type KelpieFetch } from "@/lib/kelpie/client";
import { caseFromIncident, incidentStatusFor, kelpieObservable, kelpieSeverity } from "@/lib/kelpie/map";

const inc = {
  id: "8f3a2c1e-0000-4000-8000-000000000001",
  ref: 42,
  title: "Suspicious inbox rule",
  description: "Rule hides invoices.",
  severity: "informational" as const,
  attackTechniques: ["T1564.008"],
  createdAt: new Date("2026-10-06T01:00:00Z"),
  firstSeen: new Date("2026-10-06T00:40:00Z"),
  tenantSlug: "river-clinic",
  links: [{ kind: "asset", label: "WEB-03" }, { kind: "identity", label: "jsmith" }, { kind: "observable", label: "203.0.113.9" }],
};

describe("Kelpie mapping", () => {
  it("builds an idempotent case body from an incident", () => {
    const body = caseFromIncident(inc, "https://soc.example.au/");
    expect(body).toMatchObject({
      title: "Suspicious inbox rule",
      severity: "low",
      tlp: "amber",
      classification: "other",
      occurredAt: "2026-10-06T00:40:00.000Z",
      detectedAt: "2026-10-06T01:00:00.000Z",
      sourceSystem: "blaksoc",
      sourceReference: inc.id,
      sourceUrl: `https://soc.example.au/soc/incidents/${inc.id}`,
    });
    expect(body.summary).toContain("INC-42");
    expect(body.summary).toContain("Assets: WEB-03.");
    expect(body.tags).toEqual(["blaksoc:INC-42", "tenant:river-clinic", "attack:T1564.008", "host:WEB-03"]);
  });

  it("never sends an occurrence time after detection", () => {
    const late = caseFromIncident({ ...inc, firstSeen: new Date("2026-10-06T02:00:00Z") }, "https://x");
    expect(late.occurredAt).toBe(late.detectedAt);
    expect(caseFromIncident({ ...inc, firstSeen: null }, "https://x").occurredAt).toBe("2026-10-06T01:00:00.000Z");
  });

  it("maps statuses, severities and observables", () => {
    expect(incidentStatusFor("in_progress")).toBe("INVESTIGATING");
    expect(incidentStatusFor("closed")).toBe("CLOSED");
    expect(incidentStatusFor("weird")).toBeNull();
    expect(kelpieSeverity("critical")).toBe("critical");
    expect(kelpieObservable("ipv4:203.0.113.9")).toEqual({ type: "ip", value: "203.0.113.9" });
    expect(kelpieObservable("sha256:abc")).toEqual({ type: "file_hash", value: "abc" });
    expect(kelpieObservable("cve:CVE-2024-1")).toEqual({ type: "other", value: "CVE-2024-1" });
    expect(kelpieObservable("nocolon")).toBeNull();
  });
});

describe("Kelpie client", () => {
  const reply = (status: number, body: unknown, seen: { url?: string; auth?: string; body?: string }[] = []): KelpieFetch => async (url, init) => {
    seen.push({ url, auth: init.headers.authorization, body: init.body });
    return { status, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) };
  };

  it("creates a case with the bearer token and accepts a replay", async () => {
    const seen: { url?: string; auth?: string; body?: string }[] = [];
    const k = new KelpieClient("https://kelpie.example.au/", "klp_secret", reply(200, { id: "c1", caseNumber: "KP-2026-0001", created: false }, seen));
    const out = await k.createCase({ title: "t", sourceSystem: "blaksoc", sourceReference: "r" });
    expect(out.created).toBe(false);
    expect(seen[0]).toMatchObject({ url: "https://kelpie.example.au/api/v1/cases", auth: "Bearer klp_secret" });
    expect(k.caseUrl("c1")).toBe("https://kelpie.example.au/cases/c1");
  });

  it("redacts tokens from errors and marks permanent failures", async () => {
    const k = new KelpieClient("https://k", "klp_secret", reply(401, "bad token klp_secret Bearer klp_secret"));
    const err = await k.getCase("c1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KelpieError);
    expect((err as KelpieError).message).not.toContain("klp_secret");
    expect((err as KelpieError).permanent).toBe(true);
    expect(new KelpieError("x", 503).permanent).toBe(false);
    expect(new KelpieError("x", 429).permanent).toBe(false);
  });
});
