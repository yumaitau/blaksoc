import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { admitScan, certWindow, classifyObservation, emptyScanBudget, SCAN_LIMITS } from "@/lib/asm/scan";
import { dedupeExposures, sanitiseExposure } from "@/lib/credentials/exposure";
import { parseDmarcXml, unwrapDmarc } from "@/lib/email/dmarc";
import { matchLookalikes, permutations } from "@/lib/email/lookalike";
import { parseDmarc, parsePosture, parseSpf } from "@/lib/email/posture";
import { connectorDef } from "@/lib/connectors/registry";
import { adminReportUrl, createGoogleProvider, directoryUrl, fixtureGoogleAlerts } from "@/lib/providers/google/provider";

const DMARC_XML = `<?xml version="1.0"?>
<feedback><report_metadata><org_name>Example</org_name><report_id>r1</report_id></report_metadata>
<policy_published><domain>river.example</domain></policy_published>
<record><row><source_ip>203.0.113.8</source_ip><count>2</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row></record>
<record><row><source_ip>203.0.113.9</source_ip><count>4</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record>
</feedback>`;

function zipStore(filename: string, data: Buffer): Buffer {
  const name = Buffer.from(filename);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  return Buffer.concat([local, name, data]);
}

describe("email posture parsing", () => {
  it("flags two SPF records, more than 10 lookups, and p=none with pct", () => {
    const includes = Array.from({ length: 11 }, (_, i) => `spf${i}.example`);
    const txt = [
      { name: "river.example", values: [`v=spf1 ${includes.map((name) => `include:${name}`).join(" ")} -all`, "v=spf1 -all"] },
      ...includes.map((name) => ({ name, values: ["v=spf1 -all"] })),
      { name: "_dmarc.river.example", values: ["v=DMARC1; p=none; pct=100"] },
    ];
    const spf = parseSpf("river.example", txt);
    expect(spf.multiple).toBe(true);
    expect(spf.lookupCount).toBe(11);
    expect(spf.tooManyLookups).toBe(true);
    const dmarc = parseDmarc("river.example", txt);
    expect(dmarc).toMatchObject({ policy: "none", pct: 100 });
    const posture = parsePosture("river.example", { txt });
    expect(posture.findings.map((f) => f.code)).toEqual(expect.arrayContaining(["SPF-MULTIPLE", "SPF-LOOKUPS", "DMARC-NONE", "DKIM-MISSING"]));
    expect(posture.findings.find((f) => f.code === "DMARC-NONE")?.title).toContain("pct=100");
    expect(posture.findings.find((f) => f.code === "SPF-MULTIPLE")?.title).toContain("Ask your IT provider");
  });

  it("treats MTA-STS, TLS-RPT, and BIMI as informational", () => {
    const txt = [
      { name: "river.example", values: ["v=spf1 -all"] },
      { name: "_dmarc.river.example", values: ["v=DMARC1; p=reject"] },
      { name: "google._domainkey.river.example", values: ["v=DKIM1; p=abc"] },
      { name: "_mta-sts.river.example", values: ["v=STSv1; id=1"] },
      { name: "_smtp._tls.river.example", values: ["v=TLSRPTv1; rua=mailto:tls@river.example"] },
      { name: "default._bimi.river.example", values: ["v=BIMI1; l=https://river.example/bimi.svg"] },
    ];
    const posture = parsePosture("river.example", { txt });
    expect(posture.score).toBe(100);
    expect(posture.findings).toEqual([]);
    expect(posture.mtaSts.present).toBe(true);
    expect(posture.tlsRpt.present).toBe(true);
    expect(posture.bimi.present).toBe(true);
  });

  it("reads gzip and zip DMARC aggregates", () => {
    const gz = unwrapDmarc("report.xml.gz", gzipSync(DMARC_XML));
    const zip = unwrapDmarc("report.zip", zipStore("report.xml", Buffer.from(DMARC_XML)));
    expect(parseDmarcXml(gz)).toMatchObject({ reportId: "Example:r1", domain: "river.example", pass: 4, fail: 2, unknownSenders: 1 });
    expect(parseDmarcXml(zip).reportId).toBe("Example:r1");
  });

  it("raises a lookalike only when certificate transparency has a new name", () => {
    expect(permutations("wattle.example")).toContain("watt1e.example");
    const hits = matchLookalikes(
      "wattle.example",
      [{ name: "watt1e.example", loggedAt: "2026-01-02T00:00:00.000Z", issuer: "Example CA", logId: "ct-99" }],
      [{ domain: "watt1e.example", registeredAt: "2026-01-01T00:00:00.000Z", registrar: "Example Registrar" }],
      [],
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ domain: "watt1e.example", registeredAt: "2026-01-01T00:00:00.000Z", ct: { logId: "ct-99" } });
    expect(matchLookalikes("wattle.example", [{ name: "watt1e.example", loggedAt: "2026-01-02", issuer: "Example CA", logId: "ct-99" }], [], ["watt1e.example"])).toEqual([]);
  });
});

describe("external scan classification", () => {
  const now = new Date("2026-06-01T00:00:00.000Z");

  it("warns at 30, 14, and 3 days and marks exposed RDP, SMB, and VPN-with-KEV as P1", () => {
    expect(certWindow(new Date("2026-07-11T00:00:00.000Z"), now)).toBeNull();
    expect(certWindow(new Date("2026-06-21T00:00:00.000Z"), now)).toBe(30);
    expect(certWindow(new Date("2026-06-11T00:00:00.000Z"), now)).toBe(14);
    expect(certWindow(new Date("2026-06-03T00:00:00.000Z"), now)).toBe(3);
    const rdp = classifyObservation({ host: "a.example", ip: "203.0.113.1", port: 3389, service: "rdp", request: "r", response: "p", tlsNotAfter: "2026-06-21T00:00:00.000Z" }, now);
    expect(rdp.p1).toBe(true);
    expect(rdp.certWindow).toBe(30);
    expect(rdp.evidence).toEqual({ request: "r", response: "p" });
    expect(classifyObservation({ host: "b.example", ip: "203.0.113.2", port: 445, service: "smb", request: "r", response: "p" }, now).p1).toBe(true);
    expect(classifyObservation({ host: "c.example", ip: "203.0.113.3", port: 443, service: "vpn", kev: false, request: "r", response: "p" }, now).p1).toBe(false);
    expect(classifyObservation({ host: "c.example", ip: "203.0.113.3", port: 443, service: "vpn", kev: true, cve: "CVE-2024-0001", request: "r", response: "p" }, now).p1).toBe(true);
  });

  it("keeps one scan per tenant and six hosts a minute", () => {
    const budget = emptyScanBudget();
    expect(SCAN_LIMITS).toEqual({ perTenantConcurrency: 1, hostsPerMinute: 6 });
    expect(admitScan(budget, "t1", 6, 1_000)).toBe(true);
    expect(admitScan(budget, "t1", 1, 1_000)).toBe(false);
    budget.inFlight.delete("t1");
    expect(admitScan(budget, "t1", 1, 2_000)).toBe(false);
    expect(admitScan(budget, "t1", 1, 61_000)).toBe(true);
  });
});

describe("credential exposure rows", () => {
  it("drops plaintext passwords and keeps one row per user and breach", () => {
    const clean = sanitiseExposure({ identity: "Ada@River.example", breach: "Collection #1", source: "hibp", observedAt: "2024-03-01", dataClasses: ["email", "passwords", "plaintext-password"], password: "must-not-be-stored" });
    expect(clean).toEqual({ identity: "ada@river.example", breach: "Collection #1", source: "hibp", observedAt: "2024-03-01", dataClasses: ["email", "password-hash"] });
    expect(JSON.stringify(clean)).not.toContain("must-not-be-stored");
    expect(dedupeExposures([clean, clean])).toHaveLength(1);
  });
});

describe("google workspace connector", () => {
  it("is available and emits the five fixture alerts, devices, and approval-shaped responses", async () => {
    const def = connectorDef("google-workspace");
    expect(def?.status).toBe("available");
    expect(def?.capabilities).toEqual(expect.arrayContaining(["events", "assets", "identity_response"]));
    expect(def?.config.safeParse({ customerId: "my_customer", domain: "wattle.example" }).success).toBe(true);
    expect(def?.secrets.safeParse({ clientEmail: "svc@example.iam.gserviceaccount.com", privateKey: "pem" }).success).toBe(true);
    const provider = createGoogleProvider({ customerId: "my_customer", domain: "wattle.example", mode: "fixture" }, {});
    const { alerts } = await provider.getAlerts({ since: new Date(0) });
    expect(alerts.map((a) => a.title)).toEqual(["Suspicious login", "2-step verification disabled", "Admin privilege granted", "Mass external share", "Third-party OAuth grant"]);
    expect(fixtureGoogleAlerts("wattle.example").map((a) => a.ruleId)).toEqual(alerts.map((a) => a.ruleId));
    const assets = await provider.getAssets();
    expect(assets.map((a) => a.os)).toEqual([null, "ChromeOS", "Android"]);
    expect(assets.map((a) => a.kind)).toEqual(["identity", "endpoint", "endpoint"]);
    const suspended = await provider.executeResponseAction({ action: "suspend_user", assetExternalId: "ada@wattle.example" });
    expect(suspended).toMatchObject({ ok: true, message: "fixture suspend_user on ada@wattle.example" });
    expect(provider.supportedActions()).toEqual(expect.arrayContaining(["suspend_user", "sign_out", "reset_signin_cookies", "revoke_oauth_token"]));
    expect(adminReportUrl("login", "my_customer")).toContain("https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login");
    expect(directoryUrl("chromeos", "my_customer")).toContain("/devices/chromeos");
    const live = createGoogleProvider({ customerId: "my_customer", domain: "wattle.example", mode: "live" }, {});
    await expect(live.getAlerts({})).rejects.toThrow(/admin\.googleapis\.com/);
  });
});
