import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import { connectorDef } from "@/lib/connectors/registry";
import { FileArchiveStore } from "@/lib/hosting/store";
import { assertDataPlaneStoresInAustralia, assertHostingEnv, assertSearchNodeInAustralia, componentsOutsideAustralia, egressOpensTheWorld, firstSearchNodeAttributes, helmBlockScalar, helmScalar, HOSTING_COMPONENT_NAMES, hostingComponents, type DataPlaneRegions } from "@/lib/hosting/profile";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function store(): Promise<{ root: string; store: FileArchiveStore }> {
  const root = await mkdtemp(path.join(tmpdir(), "blaksoc-store-"));
  roots.push(root);
  return { root, store: new FileArchiveStore(root) };
}

describe("archive object store", () => {
  it("round-trips both Australian regions and rejects the rest", async () => {
    const { store: files } = await store();
    await files.put("ap-southeast-2", "syslog/t/a.log", "sydney");
    await files.put("ap-southeast-4", "syslog/t/b.log", "melbourne");
    expect(await files.get("ap-southeast-2", "syslog/t/a.log")).toBe("sydney");
    expect(await files.list("ap-southeast-4", "syslog/t/")).toEqual(["syslog/t/b.log"]);
    await expect(files.put("us-east-1", "syslog/t/c.log", "no")).rejects.toThrow(/Australia/);
    await expect(files.put("ap-southeast-2", "../etc/passwd", "no")).rejects.toThrow(/archive key/);
    await expect(files.get("ap-southeast-2", "syslog/missing.log")).rejects.toThrow(/missing/);
  });
});

describe("hosting profile", () => {
  it("keeps chart residency inside Australia and pins k3s to one replica", async () => {
    const root = path.resolve(import.meta.dirname, "../..");
    const base = await readFile(path.join(root, "deploy/helm/blaksoc/values.yaml"), "utf8");
    const k3s = await readFile(path.join(root, "deploy/helm/blaksoc/values-k3s.yaml"), "utf8");
    expect(helmScalar(base, "AI_DATA_RESIDENCY")).toBe("AU");
    expect(helmScalar(k3s, "AI_DATA_RESIDENCY")).toBe("AU");
    expect(helmScalar(base, "BLAKSOC_ARCHIVE_DIR")).toBe("/tmp/blaksoc-archive");
    expect(helmBlockScalar(base, "web", "replicas")).toBe("2");
    expect(helmBlockScalar(k3s, "web", "replicas")).toBe("1");
    expect(helmBlockScalar(k3s, "worker", "replicas")).toBe("1");
    expect(k3s).toContain("enabled: false");
    const chart = parse(base) as { networkPolicy: { egressCidrs: string[] }; dataPlane: DataPlaneRegions };
    const k3sChart = parse(k3s) as { networkPolicy?: { egressCidrs?: string[] } };
    expect(chart.networkPolicy.egressCidrs).toEqual([]);
    expect(egressOpensTheWorld(chart.networkPolicy.egressCidrs)).toBe(false);
    expect(egressOpensTheWorld(k3sChart.networkPolicy?.egressCidrs ?? [])).toBe(false);
    expect(egressOpensTheWorld(["0.0.0.0/0"])).toBe(true);
    expect(egressOpensTheWorld(["::/0"])).toBe(true);
    const ai = helmScalar(k3s, "AI_DATA_RESIDENCY")!;
    const pinned = hostingComponents(ai, "ap-southeast-2", chart.dataPlane);
    expect(pinned.map((row) => row.name)).toEqual([...HOSTING_COMPONENT_NAMES]);
    expect(componentsOutsideAustralia(pinned)).toEqual([]);
    expect(componentsOutsideAustralia(hostingComponents(ai, "ap-southeast-4", chart.dataPlane))).toEqual([]);
    expect(componentsOutsideAustralia(hostingComponents("US", "eu-west-1", {
      opensearch: "us-east-1",
      wazuhIndexer: "eu-west-1",
      opencti: "us-west-2",
    }))).toEqual(["US", "eu-west-1", "us-east-1", "eu-west-1", "us-west-2"]);
    const wazuh = connectorDef("wazuh")!;
    const opencti = connectorDef("opencti")!;
    expect(wazuh.config.parse({ apiUrl: "https://wazuh.internal", indexerUrl: "https://indexer.internal", region: "ap-southeast-4" })).toMatchObject({ region: "ap-southeast-4" });
    expect(() => wazuh.config.parse({ apiUrl: "https://wazuh.internal", indexerUrl: "https://indexer.internal", region: "us-east-1" })).toThrow();
    expect(opencti.config.parse({ url: "https://opencti.internal", region: "ap-southeast-2" })).toMatchObject({ region: "ap-southeast-2" });
    expect(() => opencti.config.parse({ url: "https://opencti.internal", region: "eu-central-1" })).toThrow();
    expect(() => wazuh.config.parse({ apiUrl: "https://wazuh.internal", indexerUrl: "https://indexer.internal" })).toThrow();
    assertDataPlaneStoresInAustralia(chart.dataPlane);
    const config = (parse(base) as { config: Record<string, string> }).config;
    const k3sConfig = (parse(k3s) as { config: Record<string, string> }).config;
    expect(config.OPENSEARCH_REGION).toBe(chart.dataPlane.opensearch);
    expect(config.WAZUH_INDEXER_REGION).toBe(chart.dataPlane.wazuhIndexer);
    expect(config.OPENCTI_REGION).toBe(chart.dataPlane.opencti);
    expect(k3sConfig.OPENSEARCH_REGION).toBe("ap-southeast-2");
    expect(k3sConfig.WAZUH_INDEXER_REGION).toBe("ap-southeast-2");
    expect(k3sConfig.OPENCTI_REGION).toBe("ap-southeast-2");
  });

  it("rejects a foreign data plane and a search node with no Australian region", async () => {
    expect(() => assertHostingEnv({})).not.toThrow();
    expect(() => assertHostingEnv({ OPENSEARCH_REGION: "ap-southeast-2" })).toThrow(/incomplete/);
    expect(() =>
      assertHostingEnv({
        OPENSEARCH_REGION: "ap-southeast-2",
        WAZUH_INDEXER_REGION: "ap-southeast-4",
        OPENCTI_REGION: "ap-southeast-2",
      }),
    ).not.toThrow();
    expect(() =>
      assertHostingEnv({
        OPENSEARCH_REGION: "us-east-1",
        WAZUH_INDEXER_REGION: "ap-southeast-2",
        OPENCTI_REGION: "ap-southeast-2",
      }),
    ).toThrow(/Australia/);

    const root = path.resolve(import.meta.dirname, "../..");
    const compose = parse(await readFile(path.join(root, "deploy/compose/docker-compose.yml"), "utf8")) as {
      services: {
        "opencti-search": { environment: Record<string, string> };
        "opencti-minio": { image: string };
        opencti: { environment: Record<string, string> };
      };
    };
    const wazuh = parse(await readFile(path.join(root, "deploy/wazuh/indexer-region.yml"), "utf8")) as {
      services: { "wazuh.indexer": { environment: Record<string, string> } };
    };
    expect(compose.services["opencti-search"].environment["node.attr.region"]).toBe("${OPENSEARCH_REGION:-ap-southeast-2}");
    expect(compose.services["opencti-minio"].image).toBe("chainguard/minio:latest");
    expect(compose.services.opencti.environment.BLAKSOC_REGION).toBe("${OPENCTI_REGION:-ap-southeast-2}");
    expect(wazuh.services["wazuh.indexer"].environment["node.attr.region"]).toBe("ap-southeast-2");
    assertDataPlaneStoresInAustralia({ opensearch: "ap-southeast-2", wazuhIndexer: "ap-southeast-2", opencti: "ap-southeast-2" });

    const observed = {
      nodes: { abc: { attributes: { shard_indexing_pressure_enabled: "true", region: "ap-southeast-4" } } },
    };
    expect(assertSearchNodeInAustralia(firstSearchNodeAttributes(observed))).toBe("ap-southeast-4");
    expect(() => assertSearchNodeInAustralia(firstSearchNodeAttributes({ nodes: { abc: { attributes: { shard_indexing_pressure_enabled: "true" } } } }))).toThrow(/no region/);
    expect(() => assertSearchNodeInAustralia({ region: "us-east-1" })).toThrow(/Australia/);
    expect(firstSearchNodeAttributes({ nodes: {} })).toBeUndefined();
  });

  it("quotes the k6 report for 10, 50, and 200 tenants", async () => {
    const root = path.resolve(import.meta.dirname, "../..");
    const measured = JSON.parse(await readFile(path.join(root, "docs/hosting-load.json"), "utf8")) as {
      tool: string;
      profiles: { tenants: number; objects: number; bytes: number; wallMs: string; httpAvgMs: string; httpP95Ms: string; serverRssBytes: number }[];
    };
    const doc = await readFile(path.join(root, "docs/hosting.md"), "utf8");
    const worker = await readFile(path.join(root, "src/worker/index.ts"), "utf8");
    expect(measured.tool).toBe("k6");
    expect(measured.profiles.map((row) => row.tenants)).toEqual([10, 50, 200]);
    for (const row of measured.profiles) {
      expect(doc).toContain(String(row.objects));
      expect(doc).toContain(String(row.bytes));
      expect(doc).toContain(row.wallMs);
      expect(doc).toContain(row.httpAvgMs);
      expect(doc).toContain(row.httpP95Ms);
      expect(doc).toContain(String(row.serverRssBytes));
    }
    expect(doc).toContain("were not measured");
    expect(worker).toContain('name: "syslog-retain", every: 60 * 60_000');
    expect(doc).toContain("1 hour");
  });
});
