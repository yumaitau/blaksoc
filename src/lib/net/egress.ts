import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from "node:dns";
import net from "node:net";
import { Agent, type Dispatcher } from "undici";

/**
 * Where an admin-configured URL may point.
 * - `internal`: self-hosted services (Wazuh, OpenCTI, Kelpie, Ollama, vLLM) that often sit on a
 *   private network. Private and loopback addresses are allowed.
 * - `public`: SaaS endpoints (webhooks, Teams, Slack, hosted AI). Only globally routable addresses.
 * Cloud metadata, link-local, multicast and unspecified addresses are refused for both, so a
 * misconfigured or malicious integration URL cannot read instance credentials.
 */
export type Reach = "internal" | "public";

const ALWAYS_BLOCKED = new net.BlockList();
ALWAYS_BLOCKED.addSubnet("0.0.0.0", 8, "ipv4");
ALWAYS_BLOCKED.addSubnet("169.254.0.0", 16, "ipv4"); // link-local, AWS/Azure/GCP metadata
ALWAYS_BLOCKED.addAddress("100.100.100.200", "ipv4"); // Alibaba metadata
ALWAYS_BLOCKED.addSubnet("224.0.0.0", 4, "ipv4");
ALWAYS_BLOCKED.addSubnet("240.0.0.0", 4, "ipv4");
ALWAYS_BLOCKED.addAddress("::", "ipv6");
ALWAYS_BLOCKED.addSubnet("fe80::", 10, "ipv6");
ALWAYS_BLOCKED.addSubnet("ff00::", 8, "ipv6");
ALWAYS_BLOCKED.addSubnet("fd00:ec2::", 32, "ipv6"); // AWS IMDS over IPv6

const NOT_PUBLIC = new net.BlockList();
NOT_PUBLIC.addSubnet("10.0.0.0", 8, "ipv4");
NOT_PUBLIC.addSubnet("172.16.0.0", 12, "ipv4");
NOT_PUBLIC.addSubnet("192.168.0.0", 16, "ipv4");
NOT_PUBLIC.addSubnet("127.0.0.0", 8, "ipv4");
NOT_PUBLIC.addSubnet("100.64.0.0", 10, "ipv4");
NOT_PUBLIC.addSubnet("198.18.0.0", 15, "ipv4");
NOT_PUBLIC.addSubnet("192.0.0.0", 24, "ipv4");
// Documentation ranges (TEST-NET-1/2/3, RFC 5737; 2001:db8::/32, RFC 3849) are not globally reachable.
NOT_PUBLIC.addSubnet("192.0.2.0", 24, "ipv4");
NOT_PUBLIC.addSubnet("198.51.100.0", 24, "ipv4");
NOT_PUBLIC.addSubnet("203.0.113.0", 24, "ipv4");
NOT_PUBLIC.addAddress("::1", "ipv6");
NOT_PUBLIC.addSubnet("fc00::", 7, "ipv6");
NOT_PUBLIC.addSubnet("2001:db8::", 32, "ipv6");

/**
 * An IPv4-mapped IPv6 address is judged as the IPv4 address it carries, in either the dotted
 * form (::ffff:10.0.0.1) or the hex form URL parsing produces (::ffff:a00:1).
 */
function unmapped(ip: string): { ip: string; family: "ipv4" | "ipv6" } {
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (dotted) return { ip: dotted[1]!, family: "ipv4" };
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return { ip: [hi >> 8, hi & 255, lo >> 8, lo & 255].join("."), family: "ipv4" };
  }
  return { ip, family: net.isIPv6(ip) ? "ipv6" : "ipv4" };
}

/** Why `ip` is refused for `reach`, or null when it may be contacted. */
export function egressDenial(ip: string, reach: Reach): string | null {
  if (!net.isIP(ip)) return `not an IP address: ${ip}`;
  const { ip: addr, family } = unmapped(ip);
  if (ALWAYS_BLOCKED.check(addr, family)) return `${ip} is a link-local, metadata or reserved address`;
  if (reach === "public" && NOT_PUBLIC.check(addr, family)) return `${ip} is not a public address`;
  return null;
}

export class EgressDenied extends Error {
  constructor(message: string) {
    super(`egress refused: ${message}`);
    this.name = "EgressDenied";
  }
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/**
 * dns.lookup replacement for sockets: resolves every address and refuses the connection if any
 * of them is denied. Running at connect time also covers DNS answers that change after a check.
 */
export function guardedLookup(reach: Reach) {
  return (hostname: string, options: LookupOptions | number | LookupCallback, maybeCallback?: LookupCallback) => {
    const callback = (typeof options === "function" ? options : maybeCallback)!;
    const opts: LookupOptions = typeof options === "object" ? options : typeof options === "number" ? { family: options } : {};
    dnsLookup(hostname, { ...opts, all: true }, (err, addresses) => {
      if (err) return callback(err, opts.all ? [] : "");
      const denied = addresses.map((a) => egressDenial(a.address, reach)).find(Boolean);
      if (denied) return callback(Object.assign(new EgressDenied(`${hostname}: ${denied}`), { code: "EEGRESS" }), opts.all ? [] : "");
      if (opts.all) return callback(null, addresses);
      const first = addresses[0]!;
      callback(null, first.address, first.family);
    });
  };
}

/** Checks the parts of a URL a lookup never sees: scheme and literal IP hosts. */
export function assertEgressUrl(url: string | URL, reach: Reach): URL {
  const u = new URL(url);
  if (u.protocol !== "https:" && !(reach === "internal" && u.protocol === "http:")) throw new EgressDenied(`${u.protocol} is not allowed for ${reach} endpoints`);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) {
    const denied = egressDenial(host, reach);
    if (denied) throw new EgressDenied(denied);
  }
  return u;
}

export type EgressTls = { tlsVerify?: boolean; caPem?: string };

const dispatchers = new Map<string, Dispatcher>();

/** One undici agent per reach and TLS setting, with the guarded lookup on every connection. */
export function egressDispatcher(reach: Reach, tls: EgressTls = {}): Dispatcher {
  const key = `${reach}:${tls.tlsVerify !== false}:${tls.caPem ?? ""}`;
  let agent = dispatchers.get(key);
  if (!agent) {
    agent = new Agent({ connect: { rejectUnauthorized: tls.tlsVerify !== false, ca: tls.caPem, lookup: guardedLookup(reach) } });
    dispatchers.set(key, agent);
  }
  return agent;
}

/**
 * fetch for admin-configured URLs. Redirects are refused: a redirect to a literal IP would skip
 * the lookup guard, and none of the integrations need one.
 */
export async function egressFetch(url: string | URL, init: RequestInit, reach: Reach, tls: EgressTls = {}): Promise<Response> {
  const u = assertEgressUrl(url, reach);
  return fetch(u, { ...init, redirect: "error", dispatcher: egressDispatcher(reach, tls) } as RequestInit);
}
