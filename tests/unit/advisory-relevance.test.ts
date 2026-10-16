import { describe, expect, it } from "vitest";
import { softwareByAsset } from "@/lib/pipeline/software";
import { emptyProfile, osFamily, productTerms, relevanceMatcher, type EstateProfile } from "@/lib/intel/relevance";

const advisory = (title: string, extra: { summary?: string; cves?: string[]; attackTechniques?: string[] } = {}) => ({
  title, summary: extra.summary ?? null, cves: extra.cves ?? [], attackTechniques: extra.attackTechniques ?? [],
});

function estate(p: Partial<{ cves: [string, number][]; software: [string, number][]; os: [string, number][]; techniques: [string, number][] }>): EstateProfile {
  const e = emptyProfile();
  for (const [k, v] of p.cves ?? []) e.cves.set(k, v);
  for (const [k, v] of p.software ?? []) e.software.set(k, v);
  for (const [k, v] of p.os ?? []) e.os.set(k, v);
  for (const [k, v] of p.techniques ?? []) e.techniques.set(k, v);
  return e;
}

describe("productTerms", () => {
  it("strips versions, architecture and package suffixes", () => {
    expect(productTerms("openssh-server")).toEqual(["openssh"]);
    expect(productTerms("Mozilla Firefox (x64 en-AU) 128.0.3")).toEqual(["mozilla firefox", "firefox"]);
    expect(productTerms("Microsoft Exchange Server 2019 CU14")).toContain("microsoft exchange");
    expect(productTerms("Adobe Acrobat Reader DC - English")).toContain("acrobat reader");
  });

  it("drops names that are ordinary words or too short to mean anything", () => {
    expect(productTerms("less")).toEqual([]);
    expect(productTerms("file")).toEqual([]);
    expect(productTerms("bc")).toEqual([]);
    expect(productTerms("Microsoft Edge")).toEqual(["microsoft edge"]);
  });
});

describe("osFamily", () => {
  it("names the family an advisory would use", () => {
    expect(osFamily("Microsoft Windows 11 Pro 10.0.22631")).toBe("windows");
    expect(osFamily("Microsoft Windows Server 2022 Datacenter")).toBe("windows server");
    expect(osFamily("Ubuntu 22.04.4 LTS")).toBe("ubuntu");
    expect(osFamily("macOS Sonoma 14.5")).toBe("macos");
    expect(osFamily("FreeBSD 14")).toBeNull();
  });
});

describe("relevanceMatcher", () => {
  it("matches open CVEs, installed software and techniques seen in alerts, with counts", () => {
    const match = relevanceMatcher(estate({
      cves: [["CVE-2024-6387", 4]],
      software: [["openssh-server", 4], ["openssh-client", 9], ["Fortinet FortiClient VPN", 2]],
      techniques: [["T1190", 3], ["T1059.001", 7]],
    }));
    const r = match(advisory("regreSSHion: OpenSSH remote code execution", { cves: ["CVE-2024-6387", "CVE-2099-0001"], attackTechniques: ["T1190", "T1059", "T1486"] }));
    expect(r.cves).toEqual([{ label: "CVE-2024-6387", assets: 4 }]);
    expect(r.software).toEqual([{ label: "openssh", assets: 9 }]);
    // T1059 is the parent of the T1059.001 seen in alerts.
    expect(r.techniques).toEqual([{ label: "T1190", alerts: 3 }, { label: "T1059", alerts: 7 }]);
    expect(r.score).toBeGreaterThan(50);
  });

  it("matches multi-word product names in the summary, case and punctuation aside", () => {
    const match = relevanceMatcher(estate({ software: [["Fortinet FortiClient VPN", 2]] }));
    const r = match(advisory("Fortinet patches", { summary: "<p>Attackers exploit <b>FortiClient VPN</b>.</p>" }));
    expect(r.software.map((h) => h.label)).toEqual(["forticlient vpn"]);
  });

  it("reports the most specific software name only", () => {
    const match = relevanceMatcher(estate({ software: [["Microsoft Exchange Server 2019", 1]] }));
    const r = match(advisory("Microsoft Exchange Server vulnerability exploited"));
    expect(r.software.map((h) => h.label)).toEqual(["microsoft exchange"]);
  });

  it("does not match a word inside another word", () => {
    const match = relevanceMatcher(estate({ software: [["curl", 3]] }));
    expect(match(advisory("Curling club breach")).score).toBe(0);
    expect(match(advisory("curl SOCKS5 heap overflow")).software).toEqual([{ label: "curl", assets: 3 }]);
  });

  it("counts an operating system named in the advisory, weakly", () => {
    const match = relevanceMatcher(estate({ os: [["Microsoft Windows Server 2022", 2], ["Microsoft Windows 11 Pro", 10]] }));
    const r = match(advisory("Microsoft Windows privilege escalation"));
    expect(r.os).toEqual([{ label: "windows server", assets: 2 }, { label: "windows", assets: 10 }]);
    expect(r.score).toBe(5);
  });

  it("scores nothing for an estate that shares nothing with the advisory", () => {
    const match = relevanceMatcher(estate({ software: [["openssh-server", 1]], techniques: [["T1003.001", 2]] }));
    expect(match(advisory("Ivanti Connect Secure zero-day", { cves: ["CVE-2025-0282"], attackTechniques: ["T1190"] })).score).toBe(0);
  });
});

describe("softwareByAsset", () => {
  it("groups packages by blakSOC asset, unique and sorted, skipping unknown agents", () => {
    const assetOf = (ext: string) => ({ "001": "asset-1", "002": "asset-2" })[ext];
    const grouped = softwareByAsset([
      { assetExternalId: "001", name: "openssl", version: "3.0.2" },
      { assetExternalId: "001", name: "curl", version: "7.81" },
      { assetExternalId: "001", name: "openssl", version: "3.0.2" },
      { assetExternalId: "002", name: "Google Chrome", version: "129" },
      { assetExternalId: "999", name: "orphan", version: "1" },
    ], assetOf);
    expect(Object.fromEntries(grouped)).toEqual({
      "asset-1": [{ name: "curl", version: "7.81" }, { name: "openssl", version: "3.0.2" }],
      "asset-2": [{ name: "Google Chrome", version: "129" }],
    });
  });
});
