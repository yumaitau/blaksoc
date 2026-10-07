import { describe, expect, it, vi } from "vitest";
import { AGENT_SELECT, WazuhProvider } from "@/lib/providers/wazuh";

describe("Wazuh agent inventory", () => {
  it("selects only fields the 4.14 API accepts and maps the OS", async () => {
    // A bare `os` makes the API answer 400, which failed every asset sync on the first real manager.
    expect(AGENT_SELECT.split(",")).not.toContain("os");
    const paths: string[] = [];
    const provider = new WazuhProvider({ apiUrl: "https://wazuh.invalid:55000", indexerUrl: "https://wazuh.invalid:9200", region: "ap-southeast-2" } as never, { apiUser: "u", apiPassword: "p", indexerUser: "u", indexerPassword: "p" });
    vi.spyOn(provider as unknown as { api: (path: string) => Promise<unknown> }, "api").mockImplementation(async (path: string) => {
      paths.push(path);
      return { data: { total_affected_items: 2, affected_items: [
        { id: "000", name: "wazuh.manager" },
        { id: "001", name: "yumait-internal-apps", ip: "172.31.49.102", status: "active", group: ["yumait-aws"], lastKeepAlive: "2026-10-07T10:43:52+00:00", os: { name: "Ubuntu", version: "24.04.4 LTS", platform: "ubuntu" } },
      ] } };
    });
    const assets = await provider.getAssets(["group:yumait-aws"]);
    const qs = new URLSearchParams(paths[0]!.split("?")[1]);
    expect(qs.get("select")).toBe(AGENT_SELECT);
    expect(qs.get("group")).toBe("yumait-aws");
    expect(assets).toHaveLength(1);
    expect(assets[0]).toMatchObject({ externalId: "001", kind: "server", os: "Ubuntu 24.04.4 LTS", ips: ["172.31.49.102"], routingKeys: ["group:yumait-aws"] });
  });
});

describe("Wazuh vulnerability states", () => {
  it("pages through every document instead of stopping at the first page", async () => {
    const provider = new WazuhProvider({ apiUrl: "https://wazuh.invalid:55000", indexerUrl: "https://wazuh.invalid:9200", region: "ap-southeast-2" } as never, { apiUser: "u", apiPassword: "p", indexerUser: "u", indexerPassword: "p" });
    const total = 12_345;
    const bodies: { search_after?: unknown[]; size: number }[] = [];
    vi.spyOn(provider as unknown as { search: (i: string, b: unknown) => Promise<unknown> }, "search").mockImplementation(async (_i: string, body: unknown) => {
      const b = body as { search_after?: unknown[]; size: number };
      bodies.push(b);
      const start = b.search_after ? Number(b.search_after[0]) + 1 : 0;
      const hits = Array.from({ length: Math.max(0, Math.min(b.size, total - start)) }, (_, k) => ({
        _source: { agent: { id: String(start + k).padStart(3, "0") }, vulnerability: { id: `CVE-2026-${start + k}` }, package: { name: "pkg" } },
        sort: [start + k],
      }));
      return { hits: { hits } };
    });
    const vulns = await provider.getVulnerabilities();
    expect(vulns).toHaveLength(total);
    expect(bodies).toHaveLength(3);
    expect(bodies[1]!.search_after).toEqual([4999]);
  });
});
