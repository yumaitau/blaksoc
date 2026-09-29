import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  CAPABILITIES, EntitlementError, LIST_PRICE_CENTS, asTier, assertEntitled, collectingTenantIds, collectionAllowed, tierAllows, type Capability, type Tier,
} from "@/lib/billing/catalogue";
import { buildQuote, quoteCsv, quotePdf, readSupplierAbn } from "@/lib/billing/invoice";

const ESSENTIALS: Capability[] = [
  "m365_monitoring", "google_monitoring", "bec_pack", "email_posture", "attack_surface", "credential_exposure", "monthly_report",
];
const STANDARD: Capability[] = ["wazuh_endpoint", "vuln_prioritisation", "essential_eight", "business_hours_response"];
const PLUS: Capability[] = ["velociraptor_dfir", "oncall_24x7", "tabletop", "board_reporting"];

const ABN = "51824753556";
const AS_OF = new Date("2026-09-29T00:00:00.000Z");

function pdfText(bytes: Uint8Array): string {
  const buf = Buffer.from(bytes);
  const latin = buf.toString("latin1");
  const parts = [latin];
  let from = 0;
  while (from < latin.length) {
    const at = latin.indexOf("stream", from);
    if (at < 0) break;
    const nl = latin.indexOf("\n", at);
    const end = nl < 0 ? -1 : latin.indexOf("endstream", nl);
    if (nl < 0 || end < 0) break;
    let body = buf.subarray(nl + 1, end);
    if (body[body.length - 1] === 0x0a) body = body.subarray(0, body.length - 1);
    if (body[body.length - 1] === 0x0d) body = body.subarray(0, body.length - 1);
    try {
      parts.push(inflateSync(body).toString("latin1"));
    } catch {
      // not a flate stream
    }
    from = end + "endstream".length;
  }
  // pdf-lib writes WinAnsi text as hex string operands inside the content stream.
  return parts.join("\n").replace(/<([0-9A-Fa-f\s]+)>/g, (token, hex: string) => {
    const digits = hex.replace(/\s+/g, "");
    if (digits.length < 2 || digits.length % 2) return token;
    let out = "";
    for (let i = 0; i < digits.length; i += 2) out += String.fromCharCode(Number.parseInt(digits.slice(i, i + 2), 16));
    return out;
  });
}

describe("plan entitlements", () => {
  it("gates every capability on the server, per tier", () => {
    expect([...CAPABILITIES].sort()).toEqual([...ESSENTIALS, ...STANDARD, ...PLUS].sort());
    const matrix: Record<Tier, { allowed: Capability[]; denied: Capability[] }> = {
      essentials: { allowed: ESSENTIALS, denied: [...STANDARD, ...PLUS] },
      standard: { allowed: [...ESSENTIALS, ...STANDARD], denied: PLUS },
      plus: { allowed: [...ESSENTIALS, ...STANDARD, ...PLUS], denied: [] },
    };
    for (const tier of Object.keys(matrix) as Tier[]) {
      for (const cap of matrix[tier].allowed) {
        expect(tierAllows(tier, cap), `${tier} ${cap}`).toBe(true);
        expect(() => assertEntitled(tier, cap)).not.toThrow();
      }
      for (const cap of matrix[tier].denied) {
        expect(tierAllows(tier, cap), `${tier} ${cap}`).toBe(false);
        try {
          assertEntitled(tier, cap);
          throw new Error(`expected ${tier} to refuse ${cap}`);
        } catch (err) {
          expect(err).toBeInstanceOf(EntitlementError);
          expect((err as EntitlementError).capability).toBe(cap);
          expect((err as EntitlementError).tier).toBe(tier);
        }
      }
    }
  });

  it("pauses collection only for providers the tier dropped", () => {
    expect(collectionAllowed("essentials", "entra")).toBe(true);
    expect(collectionAllowed("essentials", "google")).toBe(true);
    expect(collectionAllowed("essentials", "wazuh")).toBe(false);
    expect(collectionAllowed("essentials", "demo")).toBe(false);
    expect(collectionAllowed("essentials", "velociraptor")).toBe(false);
    expect(collectionAllowed("essentials", "webhook")).toBe(true);
    expect(collectionAllowed("standard", "wazuh")).toBe(true);
    expect(collectionAllowed("standard", "velociraptor")).toBe(false);
    expect(collectionAllowed("plus", "velociraptor")).toBe(true);
    expect(asTier("nope")).toBe("essentials");

    const dropped = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const kept = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const tierOf = (id: string) => (id === kept ? "standard" as const : "essentials" as const);
    expect(collectingTenantIds("wazuh", [{ tenantId: dropped }, { tenantId: kept }], tierOf)).toEqual([kept]);
    expect(collectingTenantIds("entra", [{ tenantId: dropped }], tierOf)).toEqual([dropped]);
    expect(collectingTenantIds("demo", [{ tenantId: dropped }], tierOf)).toEqual([]);
  });
});

describe("quote and invoice", () => {
  it("applies GST, the nonprofit rate, an explicit discount, and a pilot", async () => {
    const nonprofit = buildQuote({ supplierAbn: ABN, customerName: "Wattle Health", tier: "essentials", nonprofit: true, discountBps: 0, pilotEndsAt: null, asOf: AS_OF });
    expect(nonprofit.listCents).toBe(LIST_PRICE_CENTS.essentials);
    expect(nonprofit).toMatchObject({ discountBps: 2000, exGstCents: 36_000, gstCents: 3_600, incGstCents: 39_600, pilot: false });

    const explicit = buildQuote({ supplierAbn: ABN, customerName: "Wattle Health", tier: "essentials", nonprofit: true, discountBps: 1000, pilotEndsAt: null, asOf: AS_OF });
    expect(explicit).toMatchObject({ discountBps: 1000, exGstCents: 40_500, gstCents: 4_050, incGstCents: 44_550 });

    const odd = buildQuote({ supplierAbn: ABN, customerName: "Wattle Health", tier: "standard", nonprofit: false, discountBps: 333, pilotEndsAt: null, asOf: AS_OF });
    expect(odd.exGstCents).toBe(87_003);
    expect(odd.gstCents).toBe(8_700);
    expect(odd.incGstCents).toBe(odd.exGstCents + odd.gstCents);

    const full = buildQuote({ supplierAbn: ABN, customerName: "Wattle Health", tier: "plus", nonprofit: false, discountBps: 0, pilotEndsAt: null, asOf: AS_OF });
    expect(full).toMatchObject({ exGstCents: 180_000, gstCents: 18_000, incGstCents: 198_000 });

    const pilot = buildQuote({
      supplierAbn: ABN, customerName: "Wattle Health", tier: "essentials", nonprofit: true, discountBps: 0,
      pilotEndsAt: new Date("2026-12-01T00:00:00.000Z"), asOf: AS_OF,
    });
    expect(pilot).toMatchObject({ pilot: true, exGstCents: 0, gstCents: 0, incGstCents: 0 });
    const csv = quoteCsv(pilot);
    expect(csv).toContain(ABN);
    expect(csv).toContain("GST");
    expect(csv).toContain("0.00");
    const text = pdfText(await quotePdf(pilot));
    expect(text).toContain(ABN);
    expect(text).toContain("GST");

    const ended = buildQuote({
      supplierAbn: ABN, customerName: "Wattle Health", tier: "essentials", nonprofit: false, discountBps: 0,
      pilotEndsAt: new Date("2026-01-01T00:00:00.000Z"), asOf: AS_OF,
    });
    expect(ended.pilot).toBe(false);
    expect(ended.exGstCents).toBe(45_000);

    expect(() => buildQuote({ supplierAbn: "123", customerName: "Wattle Health", tier: "essentials", nonprofit: false, discountBps: 0, pilotEndsAt: null, asOf: AS_OF })).toThrow(/11 digits/);
    expect(readSupplierAbn("")).toBeNull();
    expect(readSupplierAbn("123")).toBeNull();
    expect(readSupplierAbn("51 824 753 556")).toBe(ABN);
    expect(readSupplierAbn(ABN)).toBe(ABN);
  });
});
