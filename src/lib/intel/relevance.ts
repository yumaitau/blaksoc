/**
 * Which advisories touch an estate. An advisory is relevant when it names a CVE open on an asset, software or an
 * operating system installed there, or an ATT&CK technique seen in the estate's real alerts. Pure: the caller loads
 * the estate profile; reasons are returned so an analyst can see why, and judge a loose name match.
 */

export type EstateProfile = {
  /** Open CVE → assets affected. */
  cves: Map<string, number>;
  /** Installed package name (as reported) → assets with it. */
  software: Map<string, number>;
  /** Operating system string → assets running it. */
  os: Map<string, number>;
  /** Technique id → active-lane alerts in the window. */
  techniques: Map<string, number>;
};

export type Hit = { label: string; assets?: number; alerts?: number };
export type Relevance = { score: number; cves: Hit[]; software: Hit[]; os: Hit[]; techniques: Hit[] };
export type AdvisoryText = { title: string; summary: string | null; cves: string[]; attackTechniques: string[] };

export const emptyProfile = (): EstateProfile => ({ cves: new Map(), software: new Map(), os: new Map(), techniques: new Map() });

/** Lower case words, keeping characters product names use (node.js, c++, 7-zip becomes "7 zip"). */
export function words(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/<[^>]*>/g, " ")
    .replace(/[^a-z0-9+#.]+/g, " ")
    .split(" ")
    .map((w) => w.replace(/^\.+|\.+$/g, ""))
    .filter(Boolean);
}

// Package names that are also ordinary English, or too generic to say anything about an advisory.
const STOP = new Set([
  "base", "bind9-libs", "client", "common", "console", "core", "data", "desktop", "dialog", "driver", "edge", "file", "files", "find", "framework", "info",
  "init", "keyboard", "less", "library", "linux", "locales", "login", "make", "manager", "management", "microsoft", "mount", "office", "package", "patch", "plugin",
  "runtime", "screen", "security", "sensible", "server", "service", "shared", "support", "system", "time", "tools", "update", "utils", "which", "windows",
]);
const VENDORS = new Set(["adobe", "apple", "atlassian", "cisco", "citrix", "fortinet", "google", "ivanti", "microsoft", "mozilla", "oracle", "vmware", "zoom"]);
const SUFFIX = /\s(server|client|common|core|bin|utils|libs|daemon|data|tools|x64|x86|amd64|arm64|64 bit|32 bit|dc)$/;
const VERSION = /\s(v?\d[\w.]*|cu\d+|sp\d+|(cumulative )?update \d+)$/;

/** Phrases an advisory would use for one installed package, or none when the name says too little. */
export function productTerms(name: string): string[] {
  let n = name.toLowerCase().replace(/\(.*?\)/g, " ").split(" - ")[0]!;
  n = words(n).join(" ");
  for (let prev = ""; prev !== n; ) {
    prev = n;
    n = n.replace(VERSION, "").replace(SUFFIX, "").trim();
  }
  const terms = new Set<string>();
  const add = (t: string) => {
    if (t.length >= 4 && !STOP.has(t) && !/^\d/.test(t)) terms.add(t);
  };
  add(n);
  const [first, ...rest] = n.split(" ");
  if (first && VENDORS.has(first) && rest.length) {
    add(rest.join(" "));
    if (rest[0]!.length >= 6) add(rest[0]!);
  }
  return [...terms];
}

const OS_FAMILIES: [RegExp, string][] = [
  [/windows server/i, "windows server"],
  [/windows/i, "windows"],
  [/mac ?os|darwin/i, "macos"],
  [/ubuntu/i, "ubuntu"],
  [/debian/i, "debian"],
  [/red hat|rhel/i, "red hat enterprise linux"],
  [/centos/i, "centos"],
  [/rocky/i, "rocky linux"],
  [/alma/i, "almalinux"],
  [/ios\b|ipados/i, "ios"],
  [/android/i, "android"],
];

export function osFamily(os: string): string | null {
  return OS_FAMILIES.find(([rx]) => rx.test(os))?.[1] ?? null;
}

/** Every 1 to 4 word phrase in the text, so a multi-word product name is a set lookup. */
function phrases(text: string): Set<string> {
  const w = words(text);
  const out = new Set<string>();
  for (let i = 0; i < w.length; i++) {
    for (let k = 1; k <= 4 && i + k <= w.length; k++) out.add(w.slice(i, i + k).join(" "));
  }
  return out;
}

/** A technique counts when the alert names it, a sub-technique of it, or its parent. */
function techniqueHits(named: string[], seen: Map<string, number>): Hit[] {
  const out: Hit[] = [];
  for (const id of new Set(named.map((t) => t.toUpperCase()))) {
    let alerts = 0;
    for (const [have, n] of seen) {
      const h = have.toUpperCase();
      if (h === id || h.startsWith(`${id}.`) || id.startsWith(`${h}.`)) alerts += n;
    }
    if (alerts) out.push({ label: id, alerts });
  }
  return out;
}

/** Index the estate once, then score any number of advisories against it. */
export function relevanceMatcher(estate: EstateProfile) {
  const terms = new Map<string, { label: string; assets: number }>();
  for (const [name, assets] of estate.software) {
    for (const t of productTerms(name)) {
      // Several packages map to one term (openssh-client, openssh-server); the widest spread stands for it.
      terms.set(t, { label: t, assets: Math.max(assets, terms.get(t)?.assets ?? 0) });
    }
  }
  const families = new Map<string, number>();
  for (const [os, assets] of estate.os) {
    const f = osFamily(os);
    if (f) families.set(f, (families.get(f) ?? 0) + assets);
  }

  return (a: AdvisoryText): Relevance => {
    const text = phrases(`${a.title} ${a.summary ?? ""}`);
    const cves = a.cves.flatMap((c) => (estate.cves.has(c) ? [{ label: c, assets: estate.cves.get(c)! }] : []));
    const software: Hit[] = [];
    for (const [t, hit] of terms) if (text.has(t)) software.push({ label: hit.label, assets: hit.assets });
    // "windows server" also matches plain "windows"; report the most specific only.
    const os = [...families].filter(([f]) => text.has(f) || (f === "windows server" && text.has("windows"))).map(([label, assets]) => ({ label, assets }));
    const techniques = techniqueHits(a.attackTechniques, estate.techniques);
    // "exchange" adds nothing beside "microsoft exchange".
    const named = software.filter((h) => !software.some((o) => o !== h && ` ${o.label} `.includes(` ${h.label} `)));
    const score = 50 * Math.min(cves.length, 3) + 20 * Math.min(named.length, 3) + 10 * Math.min(techniques.length, 3) + (os.length ? 5 : 0);
    return { score, cves, software: named.sort((x, y) => (y.assets ?? 0) - (x.assets ?? 0)).slice(0, 5), os, techniques };
  };
}
