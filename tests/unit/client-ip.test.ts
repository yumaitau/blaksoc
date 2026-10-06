import { describe, expect, it } from "vitest";
import { clientIpFromForwarded, parseTrustedProxies } from "@/lib/net/client-ip";

describe("client address behind proxies", () => {
  const vpc = parseTrustedProxies("10.0.0.0/16, fd00::/8, nonsense, 300.1.1.1/8");

  it("parses trusted proxy CIDRs and drops invalid ones", () => {
    expect(vpc).toEqual(["10.0.0.0/16", "fd00::/8"]);
  });

  it("ignores addresses a client prepends to X-Forwarded-For", () => {
    // Client claims 192.0.2.10; the load balancer appended the real address, then the ingress appended the LB.
    expect(clientIpFromForwarded("192.0.2.10, 203.0.113.7, 10.0.1.5", vpc)).toBe("203.0.113.7");
    expect(clientIpFromForwarded("203.0.113.7", vpc)).toBe("203.0.113.7");
  });

  it("trusts only a single-entry header when no proxies are configured", () => {
    expect(clientIpFromForwarded("203.0.113.7", [])).toBe("203.0.113.7");
    expect(clientIpFromForwarded("192.0.2.10, 203.0.113.7", [])).toBeNull();
  });

  it("returns nothing when every hop is a proxy or the header is malformed", () => {
    expect(clientIpFromForwarded("10.0.1.5, 10.0.2.6", vpc)).toBeNull();
    expect(clientIpFromForwarded("not-an-ip", vpc)).toBeNull();
    expect(clientIpFromForwarded(null, vpc)).toBeNull();
  });
});
