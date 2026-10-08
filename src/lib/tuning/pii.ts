/**
 * Heuristics for text that must never carry customer identifiers (tuning agent memory, identifiers handed to
 * the agent). Deliberately conservative about dotted names: rule ids such as `google.login.suspicious` or
 * `T1059.001` pass, while names ending in a DNS suffix (`ws-01.corp.local`, `mail.example.com.au`) do not.
 */

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+/;
const IPV4 = /(^|[^\d.])(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.]*\d)/;
/** Full or compressed IPv6 (at least three groups, or a `::`), not a time like 10:30:00. */
const IPV6 = /(^|[^0-9A-Fa-f:])(([0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,7}:|:(:[0-9A-Fa-f]{1,4}){1,7}|([0-9A-Fa-f]{1,4}:)+(:[0-9A-Fa-f]{1,4})+)(?![0-9A-Fa-f:])/;
const DOTTED = /\b[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9-]+)+\b/g;
/** Last labels that make a dotted name a host or domain. */
const DNS_SUFFIXES = new Set([
  "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co", "au", "nz", "uk", "us", "ca", "de", "fr", "eu", "jp", "cn", "in",
  "local", "localdomain", "lan", "internal", "intranet", "corp", "home", "localhost", "arpa", "cloud", "app", "dev", "site", "online", "tech",
]);

const isTime = (s: string) => /^\d{1,2}:\d{2}(:\d{2})?$/.test(s);

export function looksLikeHostname(token: string): boolean {
  const labels = token.toLowerCase().split(".");
  if (labels.length < 2) return false;
  return DNS_SUFFIXES.has(labels.at(-1)!);
}

/** What kind of identifier `text` appears to contain, or null. */
export function piiKind(text: string): "email" | "ipv4" | "ipv6" | "hostname" | null {
  if (EMAIL.test(text)) return "email";
  if (IPV4.test(text)) return "ipv4";
  const v6 = IPV6.exec(text);
  if (v6 && !isTime(v6[2]!)) return "ipv6";
  for (const m of text.matchAll(DOTTED)) if (looksLikeHostname(m[0])) return "hostname";
  return null;
}

/** Control characters other than tab and newline removed; CRLF normalised. */
export function stripControl(text: string): string {
  return text.replace(/\r\n?/g, "\n").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u0080-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, "");
}
