import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FileArchiveStore } from "@/lib/hosting/store";
import { componentsOutsideAustralia, helmBlockScalar, helmScalar, hostingComponents } from "@/lib/hosting/profile";

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
    const ai = helmScalar(k3s, "AI_DATA_RESIDENCY")!;
    expect(componentsOutsideAustralia(hostingComponents(ai, "ap-southeast-2"))).toEqual([]);
    expect(componentsOutsideAustralia(hostingComponents(ai, "ap-southeast-4"))).toEqual([]);
    expect(componentsOutsideAustralia(hostingComponents("US", "eu-west-1"))).toEqual(["US", "eu-west-1"]);
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
