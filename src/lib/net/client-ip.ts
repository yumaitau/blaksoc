import net from "node:net";

/** Parse a comma-separated CIDR list (TRUSTED_PROXY_CIDRS). Invalid entries are dropped. */
export function parseTrustedProxies(value: string): string[] {
  return value
    .split(",")
    .map((c) => c.trim())
    .filter((c) => {
      const [addr, bits] = c.split("/");
      return !!addr && net.isIP(addr) !== 0 && (bits === undefined || /^\d{1,3}$/.test(bits));
    });
}

function blockList(cidrs: readonly string[]): net.BlockList {
  const list = new net.BlockList();
  for (const cidr of cidrs) {
    const [addr, bits] = cidr.split("/");
    const family = net.isIPv6(addr!) ? "ipv6" : "ipv4";
    if (bits === undefined) list.addAddress(addr!, family);
    else list.addSubnet(addr!, Number(bits), family);
  }
  return list;
}

/**
 * The client address from X-Forwarded-For, using the same rules as better-auth so sign-in rate
 * limits and syslog allowlists agree:
 * - With trusted proxies configured, walk the list from the right, skip trusted proxy addresses,
 *   and take the first address that is not one. Entries a client added on the left are never used.
 * - Without them, accept the header only when it has exactly one entry (one proxy appended it).
 * Returns null when no address can be trusted; callers fail closed.
 */
export function clientIpFromForwarded(forwardedFor: string | null, trustedProxies: readonly string[]): string | null {
  if (!forwardedFor) return null;
  const hops = forwardedFor.split(",").map((ip) => ip.trim()).filter(Boolean);
  if (!hops.length || hops.some((ip) => net.isIP(ip) === 0)) return null;
  if (!trustedProxies.length) return hops.length === 1 ? hops[0]! : null;
  const trusted = blockList(trustedProxies);
  for (let i = hops.length - 1; i >= 0; i--) {
    const ip = hops[i]!;
    if (!trusted.check(ip, net.isIPv6(ip) ? "ipv6" : "ipv4")) return ip;
  }
  return null;
}
