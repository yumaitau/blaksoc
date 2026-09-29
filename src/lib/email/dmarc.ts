import { gunzipSync, inflateRawSync } from "node:zlib";

export type DmarcRow = {
  sourceIp: string;
  count: number;
  disposition: string;
  dkim: string;
  spf: string;
};

export type DmarcAggregate = {
  reportId: string;
  org: string;
  domain: string;
  rows: DmarcRow[];
  pass: number;
  fail: number;
  unknownSenders: number;
};

function tag(xml: string, name: string): string {
  return xml.match(new RegExp(`<${name}>([^<]*)</${name}>`, "i"))?.[1]?.trim() ?? "";
}

/** Aggregate report XML from a mailbox attachment. gzip and zip are both accepted. */
export function unwrapDmarc(filename: string, bytes: Buffer): string {
  const name = filename.toLowerCase();
  if (name.endsWith(".gz") || (bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b)) return gunzipSync(bytes).toString("utf8");
  if (name.endsWith(".zip") || (bytes.length > 4 && bytes.readUInt32LE(0) === 0x04034b50)) return unzipFirst(bytes).toString("utf8");
  return bytes.toString("utf8");
}

function unzipFirst(bytes: Buffer): Buffer {
  if (bytes.readUInt32LE(0) !== 0x04034b50) throw new Error("zip");
  const method = bytes.readUInt16LE(8);
  const compSize = bytes.readUInt32LE(18);
  const nameLen = bytes.readUInt16LE(26);
  const extraLen = bytes.readUInt16LE(28);
  const start = 30 + nameLen + extraLen;
  const data = bytes.subarray(start, start + compSize);
  if (method === 0) return Buffer.from(data);
  if (method === 8) return inflateRawSync(data);
  throw new Error("zip");
}

export function parseDmarcXml(xml: string): DmarcAggregate {
  const org = tag(xml, "org_name");
  const reportId = tag(xml, "report_id");
  const domain = tag(xml, "domain").toLowerCase();
  if (!reportId || !domain) throw new Error("dmarc");
  const rows: DmarcRow[] = [];
  for (const block of xml.match(/<record>[\s\S]*?<\/record>/gi) ?? []) {
    rows.push({
      sourceIp: tag(block, "source_ip"),
      count: Number(tag(block, "count") || "0"),
      disposition: tag(block, "disposition"),
      dkim: tag(block, "dkim"),
      spf: tag(block, "spf"),
    });
  }
  let pass = 0;
  let fail = 0;
  let unknownSenders = 0;
  for (const row of rows) {
    const ok = row.dkim === "pass" || row.spf === "pass";
    if (ok) pass += row.count;
    else fail += row.count;
    if (row.dkim === "fail" && row.spf === "fail") unknownSenders += 1;
  }
  return { reportId: `${org}:${reportId}`, org, domain, rows, pass, fail, unknownSenders };
}
