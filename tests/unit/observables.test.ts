import { describe, expect, it } from "vitest";
import { extractObservables, isPrivateIpv4 } from "@/lib/intel/observables";

describe("extractObservables", () => {
  const obs = extractObservables({
    data: { srcip: "185.220.101.47", dstuser: "j.nguyen.admin", win: { eventdata: { commandLine: "powershell -enc AAA http://update-check.xyz/p.ps1 C:\\Windows\\svchost.exe", image: "C:\\ProgramData\\lck.exe" } } },
    syscheck: { sha256_after: "b8e0a7c3d7a6f7e8c1d0f3e2a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3" },
    full_log: "Failed login from 10.1.2.3 for bob@example.com.au re CVE-2024-3400",
  });
  const has = (type: string, value: string) => obs.some((o) => o.type === type && o.value === value);

  it("finds public IPs but not private ones by default", () => {
    expect(has("ipv4", "185.220.101.47")).toBe(true);
    expect(has("ipv4", "10.1.2.3")).toBe(false);
  });
  it("finds urls and their domains", () => {
    expect(has("url", "http://update-check.xyz/p.ps1")).toBe(true);
    expect(has("domain", "update-check.xyz")).toBe(true);
  });
  it("does not treat file names as domains", () => {
    expect(obs.some((o) => o.type === "domain" && o.value.endsWith(".exe"))).toBe(false);
    expect(obs.some((o) => o.type === "domain" && o.value.endsWith(".ps1"))).toBe(false);
  });
  it("classifies hashes, emails, CVEs and users", () => {
    expect(has("sha256", "b8e0a7c3d7a6f7e8c1d0f3e2a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3")).toBe(true);
    expect(has("email", "bob@example.com.au")).toBe(true);
    expect(has("domain", "example.com.au")).toBe(false);
    expect(has("cve", "CVE-2024-3400")).toBe(true);
    expect(has("user", "j.nguyen.admin")).toBe(true);
  });
  it("private ranges", () => {
    for (const ip of ["10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "169.254.1.1"]) expect(isPrivateIpv4(ip)).toBe(true);
    for (const ip of ["8.8.8.8", "172.32.0.1", "1.1.1.1"]) expect(isPrivateIpv4(ip)).toBe(false);
  });
});
