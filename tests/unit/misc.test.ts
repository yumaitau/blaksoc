import { describe, expect, it, beforeAll } from "vitest";
import { allHold, evaluate } from "@/lib/soar/conditions";
import { checkAiPolicy, redactPii } from "@/lib/ai/policy";
import { parseRss, tagAdvisory } from "@/worker/jobs/intel";
import { normaliseWazuhAlert, wazuhLevelToSeverity } from "@/lib/providers/wazuh";
import { permissionsFor, can, tenantsWith, type AccessContext } from "@/lib/auth/access";
import { BUILTIN_ROLES, type Permission } from "@/lib/auth/permissions";
import type { AIProvider } from "@/lib/ai/types";

beforeAll(() => {
  process.env.BLAKSOC_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
});

describe("crypto", () => {
  it("round-trips and binds to AAD", async () => {
    const { encryptSecret, decryptSecret } = await import("@/lib/crypto");
    const c = encryptSecret("s3cret", "integration:a");
    expect(decryptSecret(c, "integration:a")).toBe("s3cret");
    expect(() => decryptSecret(c, "integration:b")).toThrow();
    expect(c).not.toContain("s3cret");
  });
});

describe("playbook conditions", () => {
  const ctx = { alert: { riskScore: 72, intelVerdict: "malicious", attackTechniques: ["T1059.001"], userName: null }, asset: { criticality: 4 } };
  it("evaluates operators", () => {
    expect(evaluate({ field: "alert.riskScore", op: "gte", value: 60 }, ctx)).toBe(true);
    expect(evaluate({ field: "asset.criticality", op: "lte", value: 3 }, ctx)).toBe(false);
    expect(evaluate({ field: "alert.attackTechniques", op: "contains", value: "T1059" }, ctx)).toBe(true);
    expect(evaluate({ field: "alert.intelVerdict", op: "in", value: ["malicious", "suspicious"] }, ctx)).toBe(true);
    expect(evaluate({ field: "alert.userName", op: "neq", value: null }, ctx)).toBe(false);
    expect(allHold([{ field: "missing.path", op: "eq", value: 1 }], ctx)).toBe(false);
  });
});

describe("AI policy", () => {
  const provider = (country: string, id = "p"): AIProvider => ({ id, model: "m", residency: { region: country === "AU" ? "ap-southeast-2" : "us-east-1", country, selfHosted: false } }) as AIProvider;
  const policy = { enabled: true, allowedProviders: [], allowRawEvents: false, redactPii: true };
  it("enforces AU residency", () => {
    expect(checkAiPolicy(policy, provider("US"), "AU").allowed).toBe(false);
    expect(checkAiPolicy(policy, provider("AU"), "AU").allowed).toBe(true);
    expect(checkAiPolicy(policy, provider("US"), "ANY").allowed).toBe(true);
  });
  it("respects tenant disablement and allow-list", () => {
    expect(checkAiPolicy({ ...policy, enabled: false }, provider("AU"), "AU").allowed).toBe(false);
    expect(checkAiPolicy({ ...policy, allowedProviders: ["ollama"] }, provider("AU", "bedrock"), "AU").allowed).toBe(false);
  });
  it("redacts PII but keeps email domains", () => {
    const out = redactPii("contact jane.doe@wattle.org.au or 0412 345 678");
    expect(out).toContain("[email]@wattle.org.au");
    expect(out).toContain("[phone]");
    expect(out).not.toContain("jane.doe");
  });
});

describe("advisory ingest", () => {
  it("parses RSS and tags Australian relevance", () => {
    const xml = `<rss><channel><item><title>ACSC urges patching of CVE-2024-3400 for Australian government &amp; health</title><link>https://www.cyber.gov.au/x</link><pubDate>Mon, 01 Sep 2026 00:00:00 GMT</pubDate><description><![CDATA[<p>Critical infrastructure at risk</p>]]></description><guid>x1</guid></item></channel></rss>`;
    const [item] = parseRss(xml);
    expect(item!.title).toContain("government & health");
    expect(item!.description).toBe("Critical infrastructure at risk");
    expect(tagAdvisory("cisa-advisories", `${item!.title} ${item!.description}`).sort()).toEqual(["AUSTRALIA", "CRITICAL_INFRASTRUCTURE", "GOVERNMENT", "HEALTHCARE"]);
  });
});

describe("wazuh normalisation", () => {
  it("maps levels and fields", () => {
    expect(wazuhLevelToSeverity(3)).toBe("informational");
    expect(wazuhLevelToSeverity(12)).toBe("high");
    expect(wazuhLevelToSeverity(15)).toBe("critical");
    const a = normaliseWazuhAlert("abc", { timestamp: "2026-09-28T01:00:00Z", rule: { id: "5712", level: 10, description: "SSH brute force", groups: ["sshd"], mitre: { id: ["T1110.001"] } }, agent: { id: "007", name: "web01" }, data: { srcuser: "root" } });
    expect(a).toMatchObject({ externalId: "abc", severity: "high", assetExternalId: "007", userName: "root", attackTechniques: ["T1110.001"], routingKeys: ["agent:007"] });
    expect(normaliseWazuhAlert("m", { timestamp: "2026-01-01T00:00:00Z", agent: { id: "000" } }).assetExternalId).toBeNull();
  });
});

describe("RBAC", () => {
  const role = (k: string) => new Set(BUILTIN_ROLES.find((r) => r.key === k)!.permissions as Permission[]);
  const ctx: AccessContext = {
    principal: { userId: "u", name: "u", email: "u", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "customer_admin", tenantId: "A", permissions: role("customer_admin") }, { roleKey: "customer_readonly", tenantId: "B", permissions: role("customer_readonly") }],
    tenantIds: ["A", "B"],
    tenants: [],
  };
  it("tenant grants do not leak across tenants", () => {
    expect(can(ctx, "response:approve", "A")).toBe(true);
    expect(can(ctx, "response:approve", "B")).toBe(false);
    expect(tenantsWith(ctx, "user:manage")).toEqual(["A"]);
    expect(permissionsFor(ctx, "C").size).toBe(0);
  });
  it("customer roles never include SOC-only permissions", () => {
    for (const r of BUILTIN_ROLES.filter((r) => r.scope === "tenant")) {
      for (const p of ["alert:triage", "integration:manage", "detection:deploy", "tenant:manage", "mssp:read"] as const) expect(r.permissions).not.toContain(p);
    }
  });
  it("only managers/admins approve response actions", () => {
    const approvers = BUILTIN_ROLES.filter((r) => r.permissions.includes("response:approve")).map((r) => r.key).sort();
    expect(approvers).toEqual(["customer_admin", "platform_admin", "soc_manager"]);
  });
});
