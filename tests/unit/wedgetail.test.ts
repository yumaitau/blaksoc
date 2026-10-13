import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { normaliseWedgetail, verifyWedgetail, wedgetailEvent, WEDGETAIL_STATUSES } from "@/lib/providers/wedgetail";
import { extractObservables } from "@/lib/intel/observables";
import { ocsfForAlert } from "@/lib/ocsf/map";
import { validateOcsf } from "@/lib/ocsf/validate";
import { WEDGETAIL_CREATED, WEDGETAIL_V1 } from "../fixtures/wedgetail";

// Built at runtime: a literal signing secret, even a fake one, trips the secret scan.
const secret = "s".repeat(32);
const now = Date.parse("2026-10-13T00:00:00Z");
function signed(body: string, timestamp = String(now / 1000)) {
  return new Headers({ "X-Wedgetail-Timestamp": timestamp, "X-Wedgetail-Signature": `v1=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}` });
}

describe("Wedgetail contract", () => {
  it("verifies exact bytes and matches upstream's timestamp-dot-body scheme", () => {
    const body = JSON.stringify({ ...WEDGETAIL_CREATED, unicode: "Wedgetail — 澳" });
    const bytes = Buffer.from(body);
    expect(verifyWedgetail(bytes, signed(body), secret, now)).toBe(true);
    expect(verifyWedgetail(Buffer.from(`${body} `), signed(body), secret, now)).toBe(false);
    expect(verifyWedgetail(bytes, signed(body), "wrong", now)).toBe(false);
    expect(verifyWedgetail(bytes, signed(body), "", now)).toBe(false);
    for (const ts of [String(now / 1000 - 301), String(now / 1000 + 301), "1e10", "0x123", "invalid"]) expect(verifyWedgetail(bytes, signed(body, ts), secret, now)).toBe(false);
    for (const offset of [-300, 300]) expect(verifyWedgetail(bytes, signed(body, String(now / 1000 + offset)), secret, now)).toBe(true);
    for (const signature of ["", "v1=invalid", `v2=${"a".repeat(64)}`, `v1=${"a".repeat(64)}`]) {
      const headers = signed(body); headers.set("x-wedgetail-signature", signature);
      expect(verifyWedgetail(bytes, headers, secret, now)).toBe(false);
    }
    expect(verifyWedgetail(bytes, new Headers(), secret, now)).toBe(false);
  });

  it("maps the fictional wedgetail.alert.v1 fixture and keeps compliance references", () => {
    const event = wedgetailEvent.parse(WEDGETAIL_V1);
    if ("type" in event) throw new Error("expected summary");
    const alert = normaliseWedgetail(event);
    expect(alert).toMatchObject({ externalId: WEDGETAIL_V1.alert.id, ruleId: "WT-AWS-001", title: "Root user activity", severity: "high", occurredAt: new Date(WEDGETAIL_V1.alert.detectedAt), hostname: "aws-example", userName: WEDGETAIL_V1.entities.principal, routingKeys: [], attackTechniques: ["T1078.004"] });
    expect(alert.description).toContain("ISM-1509");
    expect(alert.raw).toMatchObject({ sourceIp: "203.0.113.10", resourceArn: WEDGETAIL_V1.entities.resource });
    expect(extractObservables(alert.raw)).toContainEqual(expect.objectContaining({ type: "ipv4", value: "203.0.113.10" }));
    const { finding } = ocsfForAlert(alert, { source: "wedgetail", sourceEventId: alert.externalId, tenantId: "11111111-1111-4111-8111-111111111111", ingestedAt: new Date(now) });
    expect(validateOcsf(finding).ok).toBe(true);
    expect(finding.metadata.product).toMatchObject({ name: "Wedgetail", vendor_name: "Yuma IT" });
  });

  it("maps the full generic webhook without retaining unknown/raw event fields", () => {
    const event = wedgetailEvent.parse({ ...WEDGETAIL_CREATED, alert: { ...WEDGETAIL_CREATED.alert, sampleEvents: [{ secret: "never store this" }] } });
    if (!("type" in event) || event.type !== "wedgetail.alert.created") throw new Error("expected creation");
    const alert = normaliseWedgetail(event);
    expect(alert.attackTechniques).toEqual(["T1078.004"]);
    expect(alert.raw).toMatchObject({ ism: ["ISM-1509"], essentialEight: ["multi-factor-authentication"], sourceIp: "198.51.100.10" });
    expect(alert.raw).not.toHaveProperty("sampleEvents");
  });

  it("validates status event timestamps and maps acknowledged, closed and reopened", () => {
    expect(WEDGETAIL_STATUSES).toEqual({
      new: "NEW", acknowledged: "TRIAGING", in_progress: "INVESTIGATING",
      closed_true_positive: "RESOLVED", closed_benign: "RESOLVED", closed_false_positive: "FALSE_POSITIVE",
      reopened: "NEW", closed: "RESOLVED",
    });
    for (const status of ["new", "acknowledged", "in_progress", "closed_true_positive", "closed_benign", "closed_false_positive"]) {
      expect(wedgetailEvent.safeParse({ type: "wedgetail.alert.updated", alert: { id: "fictional", status, updatedAt: "2026-10-13T00:00:01Z" } }).success).toBe(true);
    }
    expect(wedgetailEvent.safeParse({ type: "wedgetail.alert.updated", alert: { id: "fictional", status: "closed", updatedAt: "not-a-date" } }).success).toBe(false);
    expect(wedgetailEvent.safeParse({ type: "wedgetail.alert.updated", alert: { id: "fictional", status: "closed" } }).success).toBe(false);
    expect(wedgetailEvent.safeParse({ ...WEDGETAIL_CREATED, alert: { ...WEDGETAIL_CREATED.alert, firstSeen: "yesterday" } }).success).toBe(false);
    const combined = wedgetailEvent.parse({ ...WEDGETAIL_V1, type: "wedgetail.alert.updated", alert: { ...WEDGETAIL_V1.alert, status: "closed", updatedAt: "2026-10-13T00:00:01Z" } });
    expect(combined).toMatchObject({ type: "wedgetail.alert.updated" });
  });
});
