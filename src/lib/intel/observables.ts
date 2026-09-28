export type ObservableType = "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256" | "email" | "hostname" | "cve" | "user";
export type Observable = { type: ObservableType; value: string; field?: string };

const IPV4 = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const IPV6 = /\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b/gi;
const URL_RE = /\bhttps?:\/\/[^\s"'<>\\)]+/gi;
const EMAIL = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi;
const HASH = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;
const CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

// Things that look like domains in endpoint telemetry but are file names.
const FILE_EXT = new Set([
  "exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "js", "jse", "hta", "msi", "log", "txt", "tmp", "dat", "ini",
  "xml", "json", "yml", "yaml", "conf", "cfg", "lnk", "zip", "rar", "7z", "doc", "docx", "xls", "xlsx", "pdf", "png",
  "jpg", "gif", "evtx", "etl", "py", "sh", "so", "db", "sqlite", "pem", "key", "crt", "local", "internal", "lan",
]);

/** Field names whose values are identities rather than free text. */
const USER_FIELDS = /(^|\.)(srcuser|dstuser|targetusername|subjectusername|user|username|upn|userprincipalname)$/i;
const HOST_FIELDS = /(^|\.)(hostname|computer|workstationname|agent\.name)$/i;

export function isPrivateIpv4(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number) as [number, number];
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a >= 224;
}

function hashType(h: string): ObservableType {
  return h.length === 64 ? "sha256" : h.length === 40 ? "sha1" : "md5";
}

/** Extract observables from an arbitrary event payload. Values are normalised and deduplicated. */
export function extractObservables(payload: unknown, opts: { includePrivate?: boolean } = {}): Observable[] {
  const found = new Map<string, Observable>();
  const add = (type: ObservableType, value: string, field?: string) => {
    const v = type === "cve" ? value.toUpperCase() : ["url", "user"].includes(type) ? value : value.toLowerCase();
    const k = `${type}|${v}`;
    if (!found.has(k)) found.set(k, { type, value: v, field });
  };

  const visit = (node: unknown, path: string) => {
    if (node == null) return;
    if (typeof node === "string") return scan(node, path);
    if (typeof node === "number" || typeof node === "boolean") return;
    if (Array.isArray(node)) return node.forEach((n) => visit(n, path));
    if (typeof node === "object") {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) visit(v, path ? `${path}.${k}` : k);
    }
  };

  const scan = (s: string, field: string) => {
    if (s.length > 20_000) s = s.slice(0, 20_000);
    if (USER_FIELDS.test(field) && s && !s.endsWith("$") && s !== "-" && !/^(system|local service|network service)$/i.test(s)) {
      add("user", s, field);
    }
    if (HOST_FIELDS.test(field) && /^[a-z0-9][a-z0-9.-]{0,252}$/i.test(s)) add("hostname", s, field);

    const urls = s.match(URL_RE) ?? [];
    urls.forEach((u) => add("url", u.replace(/[.,;]+$/, ""), field));
    for (const ip of s.match(IPV4) ?? []) if (opts.includePrivate || !isPrivateIpv4(ip)) add("ipv4", ip, field);
    for (const ip of s.match(IPV6) ?? []) add("ipv6", ip, field);
    const emails = s.match(EMAIL) ?? [];
    emails.forEach((e) => add("email", e, field));
    for (const h of s.match(HASH) ?? []) add(hashType(h), h, field);
    for (const c of s.match(CVE) ?? []) add("cve", c, field);

    const emailDomains = new Set(emails.map((e) => e.split("@")[1]!.toLowerCase()));
    for (const d of s.match(DOMAIN) ?? []) {
      const lower = d.toLowerCase();
      const tld = lower.split(".").pop()!;
      if (FILE_EXT.has(tld) || /^\d+(\.\d+){3}$/.test(lower) || emailDomains.has(lower)) continue;
      add("domain", lower, field);
    }
    for (const u of urls) {
      try {
        const host = new URL(u).hostname.toLowerCase();
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(host)) add("domain", host, field);
      } catch {
        /* malformed URL: already captured as url */
      }
    }
  };

  visit(payload, "");
  return [...found.values()];
}

/** Types worth sending to external CTI (never usernames or internal hostnames). */
export const ENRICHABLE: ReadonlySet<ObservableType> = new Set(["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve"]);
