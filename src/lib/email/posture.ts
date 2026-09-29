export type DnsTxt = { name: string; values: string[] };

export type DnsSnapshot = {
  txt: DnsTxt[];
  /** Selector names checked under `selector._domainkey`. */
  dkimSelectors?: string[];
};

export type SpfResult = {
  records: string[];
  multiple: boolean;
  lookupCount: number;
  tooManyLookups: boolean;
};

export type DmarcResult = {
  record: string | null;
  policy: string | null;
  pct: number | null;
  rua: string | null;
};

export type InformationalRecord = { present: boolean; record: string | null };

export type PostureParse = {
  spf: SpfResult;
  dkim: { selectors: { name: string; record: string | null }[] };
  dmarc: DmarcResult;
  mtaSts: InformationalRecord;
  tlsRpt: InformationalRecord;
  bimi: InformationalRecord;
  score: number;
  findings: { code: string; title: string }[];
};

const LOOKUP = /^(?:a|mx|ptr)(?::|$)|^(?:exists:|include:)|(?:^redirect=)/i;

function mechanisms(record: string): string[] {
  return record.trim().split(/\s+/).slice(1);
}

function lookupCount(record: string, txt: DnsTxt[], seen: Set<string>): number {
  let n = 0;
  for (const raw of mechanisms(record)) {
    const mech = raw.replace(/^[+\-~?]/, "");
    if (!LOOKUP.test(mech)) continue;
    n += 1;
    const include = mech.match(/^include:([^ ]+)$/i)?.[1]?.toLowerCase();
    const redirect = mech.match(/^redirect=(.+)$/i)?.[1]?.toLowerCase();
    const next = include ?? redirect;
    if (!next || seen.has(next)) continue;
    seen.add(next);
    const nested = spfRecords(next, txt);
    if (nested[0]) n += lookupCount(nested[0], txt, seen);
  }
  return n;
}

function spfRecords(name: string, txt: DnsTxt[]): string[] {
  const row = txt.find((t) => t.name.toLowerCase() === name.toLowerCase());
  return (row?.values ?? []).filter((v) => v.trim().toLowerCase().startsWith("v=spf1"));
}

function oneTxt(name: string, txt: DnsTxt[], prefix: string): string | null {
  const values = txt.find((t) => t.name.toLowerCase() === name.toLowerCase())?.values ?? [];
  return values.find((v) => v.trim().toLowerCase().startsWith(prefix)) ?? null;
}

export function parseSpf(domain: string, txt: DnsTxt[]): SpfResult {
  const records = spfRecords(domain, txt);
  const lookup = records[0] ? lookupCount(records[0], txt, new Set([domain.toLowerCase()])) : 0;
  return { records, multiple: records.length > 1, lookupCount: lookup, tooManyLookups: lookup > 10 };
}

export function parseDmarc(domain: string, txt: DnsTxt[]): DmarcResult {
  const record = oneTxt(`_dmarc.${domain}`, txt, "v=dmarc1");
  if (!record) return { record: null, policy: null, pct: null, rua: null };
  const tag = (key: string) => record.match(new RegExp(`(?:^|;)\\s*${key}\\s*=\\s*([^;\\s]+)`, "i"))?.[1] ?? null;
  const pctRaw = tag("pct");
  return { record, policy: tag("p"), pct: pctRaw == null ? null : Number(pctRaw), rua: tag("rua") };
}

export function parsePosture(domain: string, dns: DnsSnapshot): PostureParse {
  const spf = parseSpf(domain, dns.txt);
  const selectors = dns.dkimSelectors?.length ? dns.dkimSelectors : ["google", "selector1"];
  const dkim = {
    selectors: selectors.map((name) => ({ name, record: oneTxt(`${name}._domainkey.${domain}`, dns.txt, "v=dkim1") })),
  };
  const dmarc = parseDmarc(domain, dns.txt);
  const mtaSts = { record: oneTxt(`_mta-sts.${domain}`, dns.txt, "v=stsv1"), present: false };
  mtaSts.present = mtaSts.record != null;
  const tlsRpt = { record: oneTxt(`_smtp._tls.${domain}`, dns.txt, "v=tlsrptv1"), present: false };
  tlsRpt.present = tlsRpt.record != null;
  const bimi = { record: oneTxt(`default._bimi.${domain}`, dns.txt, "v=bimi1"), present: false };
  bimi.present = bimi.record != null;

  const findings: { code: string; title: string }[] = [];
  if (spf.records.length === 0) {
    findings.push({ code: "SPF-MISSING", title: "Ask your IT provider to add this DNS record: v=spf1 include:_spf.google.com -all" });
  }
  if (spf.multiple) {
    findings.push({ code: "SPF-MULTIPLE", title: "Ask your IT provider to publish one SPF record. More than one SPF record makes the check fail." });
  }
  if (spf.tooManyLookups) {
    findings.push({ code: "SPF-LOOKUPS", title: `Ask your IT provider to simplify SPF. This record needs ${spf.lookupCount} DNS lookups and the limit is 10.` });
  }
  if (!dmarc.record) {
    findings.push({ code: "DMARC-MISSING", title: "Ask your IT provider to add this DNS record: v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain });
  } else if (dmarc.policy === "none") {
    const pct = dmarc.pct == null ? "" : ` The pct=${dmarc.pct} tag does not make p=none enforce.`;
    findings.push({ code: "DMARC-NONE", title: `Ask your IT provider to change DMARC from p=none to p=quarantine or p=reject.${pct}` });
  }
  if (!dkim.selectors.some((s) => s.record)) {
    findings.push({ code: "DKIM-MISSING", title: "Ask your IT provider to publish a DKIM record for a selector such as google._domainkey." });
  }

  let score = 100;
  for (const f of findings) {
    if (f.code === "SPF-MISSING" || f.code === "SPF-MULTIPLE") score -= 25;
    if (f.code === "SPF-LOOKUPS") score -= 20;
    if (f.code === "DMARC-MISSING") score -= 25;
    if (f.code === "DMARC-NONE") score -= 15;
    if (f.code === "DKIM-MISSING") score -= 15;
  }
  return { spf, dkim, dmarc, mtaSts, tlsRpt, bimi, score: Math.max(0, score), findings };
}
