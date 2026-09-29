const HOMO: Record<string, string> = { o: "0", l: "1", i: "1", e: "3", a: "4", s: "5" };

export type CtRecord = { name: string; loggedAt: string; issuer: string; logId: string };
export type WhoisRecord = { domain: string; registeredAt: string | null; registrar: string | null };

export type LookalikeHit = {
  domain: string;
  registeredAt: string | null;
  registrar: string | null;
  ct: CtRecord;
};

/** Small dnstwist-style set: omission, adjacent swap, one homoglyph, and a tld swap. */
export function permutations(domain: string): string[] {
  const parts = domain.toLowerCase().split(".");
  const name = parts[0] ?? "";
  const tld = parts.slice(1).join(".");
  const out = new Set<string>();
  for (let i = 0; i < name.length; i++) {
    const omitted = name.slice(0, i) + name.slice(i + 1);
    if (omitted) out.add(`${omitted}.${tld}`);
    if (i < name.length - 1) {
      const chars = name.split("");
      const swap = chars[i]!;
      chars[i] = chars[i + 1]!;
      chars[i + 1] = swap;
      out.add(`${chars.join("")}.${tld}`);
    }
    const homo = HOMO[name[i] ?? ""];
    if (homo) out.add(`${name.slice(0, i)}${homo}${name.slice(i + 1)}.${tld}`);
  }
  for (const alt of ["com", "net", "org", "com.au"]) {
    if (alt !== tld) out.add(`${name}.${alt}`);
  }
  out.delete(domain.toLowerCase());
  return [...out];
}

export function matchLookalikes(domain: string, ct: CtRecord[], whois: WhoisRecord[], known: string[]): LookalikeHit[] {
  const want = new Set(permutations(domain));
  const seen = new Set(known.map((k) => k.toLowerCase()));
  const hits: LookalikeHit[] = [];
  for (const row of ct) {
    const name = row.name.toLowerCase().replace(/^\*\./, "");
    if (!want.has(name) || seen.has(name)) continue;
    const w = whois.find((item) => item.domain.toLowerCase() === name);
    hits.push({ domain: name, registeredAt: w?.registeredAt ?? null, registrar: w?.registrar ?? null, ct: row });
    seen.add(name);
  }
  return hits;
}
