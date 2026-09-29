import { describe, expect, it } from "vitest";
import { normaliseSyslog, parseSyslog } from "@/lib/syslog/parse";
import { assertAuRegion } from "@/lib/syslog/retain";
import { SYSLOG_LINES } from "../fixtures/syslog";

const at = new Date("2026-06-01T00:00:00.000Z");

describe("syslog parsers", () => {
  it("reads each small-office vendor fixture", () => {
    const fortinet = parseSyslog(SYSLOG_LINES.fortinet);
    expect(fortinet).toMatchObject({ vendor: "fortinet", action: "dropped", srcIp: "203.0.113.10", dstIp: "198.51.100.20", srcPort: 54321, dstPort: 443, proto: "TCP", user: "ada", hostname: "FGT60", severity: "high" });
    expect(fortinet?.occurredAt?.toISOString()).toBe("2026-06-01T01:02:03.000Z");

    expect(parseSyslog(SYSLOG_LINES.sophos)).toMatchObject({ vendor: "sophos", action: "denied", srcIp: "203.0.113.11", dstIp: "198.51.100.21", srcPort: 12345, dstPort: 22, proto: "TCP", user: "sam", hostname: "XG230", severity: "medium" });
    expect(parseSyslog(SYSLOG_LINES.draytek)).toMatchObject({ vendor: "draytek", action: "blocked", srcIp: "203.0.113.12", dstIp: "198.51.100.22", dstPort: 443, proto: "TCP", hostname: "DrayTek", severity: "medium" });
    expect(parseSyslog(SYSLOG_LINES.mikrotik)).toMatchObject({ vendor: "mikrotik", action: "drop", srcIp: "203.0.113.13", dstIp: "198.51.100.23", srcPort: 54321, dstPort: 22, proto: "TCP", hostname: "MikroTik", severity: "medium" });
    expect(parseSyslog(SYSLOG_LINES.ubiquiti)).toMatchObject({ vendor: "ubiquiti", action: "blocked", srcIp: "203.0.113.14", dstIp: "198.51.100.24", srcPort: 54321, dstPort: 443, proto: "TCP", hostname: "UDM-Pro", severity: "medium" });
    expect(parseSyslog(SYSLOG_LINES.ubiquiti)?.occurredAt?.toISOString()).toBe("2026-06-01T01:02:03.000Z");
  });

  it("drops unknown lines and refuses a non-AU archive region", () => {
    expect(parseSyslog("hello from the router")).toBeNull();
    expect(parseSyslog(SYSLOG_LINES.fortinet)?.vendor).not.toBe("sophos");
    expect(() => assertAuRegion("us-east-1")).toThrow(/Australia/);
    expect(() => assertAuRegion("ap-southeast-2")).not.toThrow();
  });

  it("normalises a parsed line into the alert the provider returns", () => {
    const alert = normaliseSyslog({ id: "evt-1", line: SYSLOG_LINES.sophos, byteLen: Buffer.byteLength(SYSLOG_LINES.sophos), ingestedAt: at }, "tenant-a");
    expect(alert).toMatchObject({
      externalId: "evt-1",
      title: "Sophos denied",
      severity: "medium",
      category: "network",
      routingKeys: ["tenant:tenant-a"],
      raw: { line: SYSLOG_LINES.sophos, vendor: "sophos", srcIp: "203.0.113.11", bytes: Buffer.byteLength(SYSLOG_LINES.sophos) },
    });
    expect(normaliseSyslog({ id: "evt-2", line: "not a firewall line", byteLen: 4, ingestedAt: at }, "tenant-a")).toBeNull();
  });
});
