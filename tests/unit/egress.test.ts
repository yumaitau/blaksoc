import { describe, expect, it } from "vitest";
import { assertEgressUrl, egressDenial, egressFetch, guardedLookup } from "@/lib/net/egress";

describe("egress guard", () => {
  it("refuses cloud metadata and link-local addresses for every reach", () => {
    for (const ip of ["169.254.169.254", "169.254.1.1", "::ffff:169.254.169.254", "fd00:ec2::254", "fe80::1", "0.0.0.0", "100.100.100.200"]) {
      expect(egressDenial(ip, "internal"), ip).not.toBeNull();
      expect(egressDenial(ip, "public"), ip).not.toBeNull();
    }
  });

  it("lets internal integrations reach private and loopback addresses", () => {
    for (const ip of ["10.0.4.2", "172.20.0.5", "192.168.1.10", "127.0.0.1", "::1", "fd12:3456::1"]) {
      expect(egressDenial(ip, "internal"), ip).toBeNull();
    }
  });

  it("keeps public integrations on public addresses", () => {
    for (const ip of ["10.0.4.2", "172.20.0.5", "192.168.1.10", "127.0.0.1", "::1", "100.64.0.1", "::ffff:10.0.0.1"]) {
      expect(egressDenial(ip, "public"), ip).not.toBeNull();
    }
    expect(egressDenial("20.190.128.1", "public")).toBeNull();
    expect(egressDenial("2606:4700::1111", "public")).toBeNull();
  });

  it("checks schemes and literal IP hosts that never reach a DNS lookup", () => {
    expect(() => assertEgressUrl("http://169.254.169.254/latest/meta-data/", "internal")).toThrow(/metadata/);
    // URL parsing rewrites [::ffff:169.254.169.254] to the hex form [::ffff:a9fe:a9fe].
    expect(() => assertEgressUrl("https://[::ffff:169.254.169.254]/", "internal")).toThrow(/metadata/);
    expect(() => assertEgressUrl("https://[::ffff:a00:1]/", "public")).toThrow(/not a public/);
    expect(() => assertEgressUrl("http://hooks.example.com/x", "public")).toThrow(/http:/);
    expect(() => assertEgressUrl("file:///etc/passwd", "internal")).toThrow(/file:/);
    expect(assertEgressUrl("http://wazuh.internal:55000", "internal").host).toBe("wazuh.internal:55000");
  });

  it("refuses a hostname that resolves to a denied address at connect time", async () => {
    const err = await new Promise<Error | null>((resolve) => guardedLookup("public")("localhost", {}, (e) => resolve(e)));
    expect(err?.message).toMatch(/egress refused/);
    const ok = await new Promise<Error | null>((resolve) => guardedLookup("internal")("localhost", {}, (e) => resolve(e)));
    expect(ok).toBeNull();
  });

  it("fails a public fetch to a private host before any request is sent", async () => {
    await expect(egressFetch("https://127.0.0.1/", { method: "POST" }, "public")).rejects.toThrow(/not a public address/);
  });
});
