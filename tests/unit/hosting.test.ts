import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import { connectorDef } from "@/lib/connectors/registry";
import { FileArchiveStore } from "@/lib/hosting/store";
import { openctiIndicatorRequest, searchBulkBody } from "@/lib/hosting/plane-load";
import { assertDataPlaneStoresInAustralia, assertHostingEnv, assertSearchNodeInAustralia, componentsOutsideAustralia, egressOpensTheWorld, egressReachesPublicInternet, firstSearchNodeAttributes, helmBlockScalar, helmScalar, HOSTING_COMPONENT_NAMES, hostingComponents, type DataPlaneRegions } from "@/lib/hosting/profile";
import { assertAuRegion } from "@/lib/syslog/retain";

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
    const chart = parse(base) as { networkPolicy: { egressCidrs: string[]; publicHttps: boolean }; dataPlane: DataPlaneRegions };
    const k3sChart = parse(k3s) as { networkPolicy?: { egressCidrs?: string[] } };
    expect(chart.networkPolicy.egressCidrs).toEqual([]);
    expect(egressOpensTheWorld(chart.networkPolicy.egressCidrs)).toBe(false);
    // The shipped chart reaches the public internet on TCP 443 only; this is deliberate and documented.
    expect(chart.networkPolicy.publicHttps).toBe(true);
    expect(egressReachesPublicInternet(chart.networkPolicy)).toBe(true);
    expect(egressReachesPublicInternet({ egressCidrs: [], publicHttps: false })).toBe(false);
    expect(egressReachesPublicInternet({ egressCidrs: ["0.0.0.0/0"], publicHttps: false })).toBe(true);
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
    const entry = parse(await readFile(path.join(root, "deploy/wazuh/indexer-region.yml"), "utf8")) as {
      services: { "wazuh.indexer": { entrypoint: string[] } };
    };
    const raw = entry.services["wazuh.indexer"].entrypoint[2] ?? "";
    // Compose turns `$$` into `$` before the container sees the script.
    const script = raw.replaceAll("$$", "$");
    expect(entry.services["wazuh.indexer"].entrypoint[0]).toBe("/bin/bash");
    expect(raw).toContain("$$(printenv 'node.attr.region')");
    expect(script).toContain("exec /entrypoint.sh opensearchwrapper");
    const confDir = await mkdtemp(path.join(tmpdir(), "blaksoc-wazuh-"));
    roots.push(confDir);
    const conf = path.join(confDir, "opensearch.yml");
    await writeFile(conf, 'network.host: "0.0.0.0"\n');
    execFileSync("bash", ["-c", script], {
      env: { ...process.env, BLAKSOC_INDEXER_CONFIG: conf, "node.attr.region": "ap-southeast-2" },
    });
    expect(await readFile(conf, "utf8")).toContain("node.attr.region: ap-southeast-2\n");
    execFileSync("bash", ["-c", script], {
      env: { ...process.env, BLAKSOC_INDEXER_CONFIG: conf, "node.attr.region": "ap-southeast-4" },
    });
    const written = await readFile(conf, "utf8");
    expect(written).toContain("node.attr.region: ap-southeast-4\n");
    expect(written).not.toContain("ap-southeast-2");
    expect(() =>
      execFileSync("bash", ["-c", script], {
        env: { ...process.env, BLAKSOC_INDEXER_CONFIG: conf, "node.attr.region": "us-east-1" },
        stdio: "pipe",
      }),
    ).toThrow(/Australia/);
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
    const worker = await readFile(path.join(root, "src/worker/schedules.ts"), "utf8");
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
    expect(doc).toContain("was not measured");
    expect(worker).toContain('name: "syslog-retain", every: 60 * 60_000');
    expect(doc).toContain("1 hour");
  });

  it("builds Australian search and OpenCTI load bodies and quotes published AU prices", async () => {
    const bulk = searchBulkBody("ap-southeast-2", 2, "blaksoc-load");
    const lines = bulk.trim().split("\n");
    expect(lines).toHaveLength(4);
    expect(JSON.parse(lines[0]!)).toEqual({ index: { _index: "blaksoc-load", _id: "0" } });
    expect(JSON.parse(lines[1]!)).toMatchObject({ region: "ap-southeast-2", n: 0 });
    expect(() => searchBulkBody("us-east-1", 1, "blaksoc-load")).toThrow(/Australia/);

    const indicator = JSON.parse(openctiIndicatorRequest("ap-southeast-4", 3, "2026-09-29T00:00:00.000Z")) as {
      variables: { input: { name: string; pattern: string; valid_from: string } };
    };
    expect(indicator.variables.input.name).toBe("blaksoc-load-ap-southeast-4-3");
    expect(indicator.variables.input.pattern).toBe("[domain-name:value = 'load-3.invalid']");
    expect(indicator.variables.input.valid_from).toBe("2026-09-29T00:00:00.000Z");
    expect(() => openctiIndicatorRequest("eu-west-1", 0, "2026-09-29T00:00:00.000Z")).toThrow(/Australia/);

    const root = path.resolve(import.meta.dirname, "../..");
    const prices = JSON.parse(await readFile(path.join(root, "docs/hosting-prices.json"), "utf8")) as {
      aws: {
        instance: { instanceType: string; vcpu: string; memoryGib: string; regions: { region: string; usd: string }[] };
        gp3StoragePerGbMonth: { region: string; usd: string; usagetype: string }[];
      };
      australianIaas: { sizes: { slug: string; audMonthly: number; audHourly: number; regions: string[] }[] };
    };
    const doc = await readFile(path.join(root, "docs/hosting.md"), "utf8");
    expect(prices.aws.instance.instanceType).toBe("t3.small.search");
    expect(prices.aws.instance.vcpu).toBe("2");
    expect(prices.aws.instance.memoryGib).toBe("2");
    for (const row of prices.aws.instance.regions) {
      assertAuRegion(row.region);
      expect(row.usd.startsWith("0.056")).toBe(true);
    }
    for (const row of prices.aws.gp3StoragePerGbMonth) assertAuRegion(row.region);
    expect(doc).toContain("0.056");
    expect(doc).toContain("0.1464");
    expect(doc).toContain("0.146");
    expect(doc).toContain("t3.small.search");
    expect(doc).toContain("APS2-ES:GP3-Storage");
    expect(doc).toContain("APS6-ES:GP3-Storage");
    for (const size of prices.australianIaas.sizes) {
      expect(size.regions).not.toContain("sin");
      expect(doc).toContain(size.slug);
      expect(doc).toContain(`${size.audMonthly} | ${size.audHourly}`);
    }
    expect(doc).toContain("https://api.binarylane.com.au/v2/sizes");
    expect(doc).toContain("not an invoice");

    const plane = JSON.parse(await readFile(path.join(root, "docs/hosting-plane.json"), "utf8")) as {
      host: { egressCountry: string; awsAccount: boolean; dataDiskPercent: number };
      opensearch: { version: string; region: string; profiles: { tenants: number; serverTookMs: number; clientWallMs: number; errors: boolean; mem: string }[] };
      wazuhIndexer: { region: string; profiles: { serverTookMs: number; clientWallMs: number; errors: boolean; mem: string }[] };
      opencti: { region: string; searchRegion: string; readName: string; profiles: { calls: number; wallMs: number; readOk: boolean; mem: string }[] };
    };
    expect(plane.host.egressCountry).toBe("AU");
    expect(plane.host.awsAccount).toBe(false);
    assertAuRegion(plane.opensearch.region);
    assertAuRegion(plane.wazuhIndexer.region);
    assertAuRegion(plane.opencti.region);
    assertAuRegion(plane.opencti.searchRegion);
    expect(plane.opensearch.version).toBe("2.19.6");
    expect(plane.opensearch.profiles.map((row) => row.tenants)).toEqual([10, 50, 200]);
    for (const row of [...plane.opensearch.profiles, ...plane.wazuhIndexer.profiles]) {
      expect(row.errors).toBe(false);
      expect(doc).toContain(String(row.serverTookMs));
      expect(doc).toContain(String(row.clientWallMs));
      expect(doc).toContain(row.mem);
    }
    for (const row of plane.opencti.profiles) {
      expect(row.readOk).toBe(true);
      expect(doc).toContain(String(row.wallMs));
      expect(doc).toContain(row.mem);
    }
    expect(doc).toContain(plane.opencti.readName);
    expect(doc).toContain("flood-stage");
    expect(doc).toContain("not in an AWS account");
    expect(doc).toContain(String(plane.host.dataDiskPercent));
  });
});
