import { beforeEach, describe, expect, it } from "vitest";
import { connectorDef } from "@/lib/connectors/registry";
import { clearFixtureActions } from "@/lib/providers/fixture-action";
import type { SecurityEventProvider } from "@/lib/providers/types";
import { playbookInput } from "@/lib/services/playbooks";
import { stepCatalogue } from "@/lib/soar/engine";

const SECRET = { clientId: "fixture-client", clientSecret: "fixture-secret" };

function provider(name: string, config: Record<string, unknown>, secrets: Record<string, string>): SecurityEventProvider {
  const def = connectorDef(name);
  if (!def?.create) throw new Error(`${name} is not available`);
  const inst = def.create(def.config.parse(config), def.secrets.parse(secrets));
  if (inst.kind !== "events") throw new Error(`${name} is not an event provider`);
  return inst.provider;
}

async function withNoFetch<T>(run: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = (() => {
    throw new Error("network");
  }) as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = original;
  }
}

describe("containment connectors", () => {
  beforeEach(() => clearFixtureActions());

  it("publishes Defender, Cloudflare, FortiGate, and Sophos with least-privilege permissions", () => {
    expect(connectorDef("defender")!.remotePermissions).toEqual([
      "Machine.Read.All",
      "Machine.Isolate",
      "Machine.Scan",
      "Vulnerability.Read.All",
      "Alert.Read.All",
    ]);
    expect(connectorDef("cloudflare")!.capabilities).toEqual(["response"]);
    expect(connectorDef("fortinet")!.capabilities).toEqual(["response"]);
    expect(connectorDef("sophos")!.capabilities).toEqual(["events", "assets", "response"]);
    expect(connectorDef("palo-alto")!.status).toBe("planned");
    expect(connectorDef("crowdstrike")!.status).toBe("planned");
    expect(connectorDef("cloudflare")!.config.parse({ accountId: "acct" })).toMatchObject({
      accountId: "acct",
      listName: "blaksoc-block",
      mode: "fixture",
    });
    expect(connectorDef("sophos")!.config.parse({ centralId: "central" })).toMatchObject({ region: "au", mode: "fixture" });
    expect(() => connectorDef("defender")!.secrets.parse({})).toThrow();
    expect(() => connectorDef("fortinet")!.config.parse({ host: "firewall.local", addressGroup: "blk" })).toThrow();
  });

  it("returns one stable Defender incident and vulnerability, and refuses live mode before any fetch", async () => {
    const live = provider("defender", { tenantDomain: "example.org", mode: "live" }, SECRET);
    const health = await withNoFetch(() => live.health());
    expect(health.ok).toBe(false);
    expect(health.error).toMatch(/live Defender/);
    await withNoFetch(() => expect(live.executeResponseAction({ action: "isolate_endpoint", assetExternalId: "device-1" })).rejects.toThrow(/live Defender/));

    const defender = provider("defender", { tenantDomain: "example.org" }, SECRET);
    const first = await defender.getAlerts({});
    const second = await defender.getAlerts({});
    expect(first.alerts.map((row) => row.externalId)).toEqual(["defender:fixture-incident"]);
    expect(second.alerts[0]!.externalId).toBe(first.alerts[0]!.externalId);
    expect(first.alerts[0]!.title).toBe("Defender fixture incident");
    expect(first.alerts[0]!.assetExternalId).toBe("device-1");
    const vulns = await defender.getVulnerabilities!();
    expect(vulns).toEqual([expect.objectContaining({ assetExternalId: "device-1", cve: "CVE-2099-1001" })]);
    expect((await defender.health()).ok).toBe(true);

    const isolated = await defender.executeResponseAction({ action: "isolate_endpoint", assetExternalId: "device-1" });
    expect(isolated.ok).toBe(true);
    expect(isolated.message.startsWith("already")).toBe(false);
    expect((await defender.executeResponseAction({ action: "isolate_endpoint", assetExternalId: "device-1" })).message).toMatch(/^already /);
    expect((await defender.executeResponseAction({ action: "release_endpoint", assetExternalId: "device-1" })).message).toBe("released device-1");
    expect((await defender.executeResponseAction({ action: "release_endpoint", assetExternalId: "device-1" })).message).toBe("already released");
    expect((await defender.executeResponseAction({ action: "scan_endpoint", assetExternalId: "device-1" })).message).toBe("scanned device-1");
    expect((await defender.executeResponseAction({ action: "scan_endpoint", assetExternalId: "device-1" })).message).toMatch(/^already /);
  });

  it("blocks and releases an indicator on Cloudflare, FortiGate, and Sophos without calling the network", async () => {
    const cases = [
      { name: "cloudflare", product: "Cloudflare", config: { accountId: "acct", mode: "live" as const }, secrets: { apiToken: "fixture-token" }, fixture: { accountId: "acct" } },
      { name: "fortinet", product: "FortiGate", config: { host: "https://firewall.example", addressGroup: "blk", mode: "live" as const }, secrets: { apiToken: "fixture-token" }, fixture: { host: "https://firewall.example", addressGroup: "blk" } },
      { name: "sophos", product: "Sophos", config: { centralId: "central", mode: "live" as const }, secrets: SECRET, fixture: { centralId: "central" } },
    ];
    for (const row of cases) {
      const live = provider(row.name, row.config, row.secrets);
      expect((await withNoFetch(() => live.health())).error).toMatch(new RegExp(`live ${row.product}`));
      await withNoFetch(() => expect(live.executeResponseAction({ action: "block_ioc", assetExternalId: "203.0.113.50", params: { indicator: "203.0.113.50" } })).rejects.toThrow(new RegExp(`live ${row.product}`)));
      const fixture = provider(row.name, row.fixture, row.secrets);
      const blocked = await fixture.executeResponseAction({ action: "block_ioc", assetExternalId: "203.0.113.50", params: { indicator: "203.0.113.50" } });
      expect(blocked.message).toBe("blocked 203.0.113.50");
      expect((await fixture.executeResponseAction({ action: "block_ioc", assetExternalId: "203.0.113.50", params: { indicator: "203.0.113.50" } })).message).toMatch(/^already /);
      expect((await fixture.executeResponseAction({ action: "unblock_ioc", assetExternalId: "203.0.113.50", params: { indicator: "203.0.113.50" } })).message).toBe("released 203.0.113.50");
      expect((await fixture.executeResponseAction({ action: "unblock_ioc", assetExternalId: "203.0.113.50", params: { indicator: "203.0.113.50" } })).message).toBe("already released");
      expect(await fixture.getAlerts({})).toEqual(row.name === "sophos"
        ? { alerts: [expect.objectContaining({ externalId: "sophos:fixture-incident", title: "Sophos fixture alert" })], cursor: null }
        : { alerts: [], cursor: null });
    }
  });

  it("lets a playbook name the containment actions", () => {
    const keys = stepCatalogue().map((step) => step.key);
    expect(keys).toEqual(expect.arrayContaining(["scan_endpoint", "block_ioc", "unblock_ioc", "isolate_endpoint", "release_endpoint"]));
    const parsed = playbookInput.parse({
      tenantId: "00000000-0000-4000-8000-000000000001",
      name: "Contain",
      trigger: { event: "manual", conditions: [] },
      steps: [
        { id: "scan", action: "scan_endpoint", name: "Scan" },
        { id: "block", action: "block_ioc", name: "Block" },
        { id: "unblock", action: "unblock_ioc", name: "Unblock", params: { indicator: "203.0.113.50" } },
        { id: "isolate", action: "isolate_endpoint", name: "Isolate" },
        { id: "release", action: "release_endpoint", name: "Release" },
      ],
    });
    expect(parsed.steps.map((step) => step.action)).toEqual(["scan_endpoint", "block_ioc", "unblock_ioc", "isolate_endpoint", "release_endpoint"]);
  });
});
