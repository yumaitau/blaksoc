import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import { LIST_PRICE_CENTS, NONPROFIT_DISCOUNT_BPS, TIER_LABEL, type Tier } from "./catalogue";

export type QuoteInput = {
  supplierAbn: string;
  customerName: string;
  tier: Tier;
  nonprofit: boolean;
  discountBps: number;
  pilotEndsAt: Date | null;
  asOf: Date;
};

export type Quote = {
  supplierAbn: string;
  customerName: string;
  tier: Tier;
  listCents: number;
  discountBps: number;
  nonprofit: boolean;
  pilot: boolean;
  pilotEndsAt: Date | null;
  exGstCents: number;
  gstCents: number;
  incGstCents: number;
};

const ABN = /^\d{11}$/;

/** Operator-supplied ABN. Empty or malformed must not fall back to a sample number. */
export function readSupplierAbn(raw: string | undefined = process.env.BLAKSOC_SUPPLIER_ABN): string | null {
  const v = (raw ?? "").replace(/\s+/g, "");
  return ABN.test(v) ? v : null;
}

export function aud(cents: number): string {
  const sign = cents < 0 ? "-" : "";
  return `${sign}${(Math.abs(cents) / 100).toFixed(2)}`;
}

export function buildQuote(input: QuoteInput): Quote {
  if (!ABN.test(input.supplierAbn)) throw new Error("supplier ABN must be 11 digits");
  const listCents = LIST_PRICE_CENTS[input.tier];
  const pilot = input.pilotEndsAt != null && input.pilotEndsAt.getTime() > input.asOf.getTime();
  const requested = input.discountBps > 0 ? input.discountBps : input.nonprofit ? NONPROFIT_DISCOUNT_BPS : 0;
  const discountBps = Math.min(10_000, Math.max(0, requested));
  const exGstCents = pilot ? 0 : Math.round((listCents * (10_000 - discountBps)) / 10_000);
  const gstCents = Math.round((exGstCents * 10) / 100);
  return {
    supplierAbn: input.supplierAbn,
    customerName: input.customerName,
    tier: input.tier,
    listCents,
    discountBps,
    nonprofit: input.nonprofit,
    pilot,
    pilotEndsAt: input.pilotEndsAt,
    exGstCents,
    gstCents,
    incGstCents: exGstCents + gstCents,
  };
}

const csvCell = (v: string) => `"${v.replaceAll('"', '""')}"`;

export function quoteCsv(q: Quote): string {
  const note = "Indicative rate card. GST is 10% of the ex-GST amount. The Indigenous advisory group has not signed these prices off.";
  const headers = ["supplier_abn", "customer", "tier", "list_ex_gst_aud", "discount_bps", "nonprofit", "pilot", "ex_gst_aud", "gst_aud", "inc_gst_aud", "note"];
  const row = [
    q.supplierAbn,
    q.customerName,
    q.tier,
    aud(q.listCents),
    String(q.discountBps),
    q.nonprofit ? "true" : "false",
    q.pilot ? "true" : "false",
    aud(q.exGstCents),
    aud(q.gstCents),
    aud(q.incGstCents),
    note,
  ];
  return `${headers.join(",")}\n${row.map(csvCell).join(",")}\n`;
}

const clean = (s: string) => s.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "?");

export async function quotePdf(q: Quote): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const page = pdf.addPage([595, 842]);
  const draw = (text: string, y: number, size = 11, f = font) => {
    page.drawText(clean(text), { x: 48, y, size, font: f, color: rgb(0.1, 0.1, 0.1) });
  };
  draw("blakSOC quote", 780, 16, bold);
  draw(`Supplier ABN ${q.supplierAbn}`, 752);
  draw(`Customer ${q.customerName}`, 732);
  draw(`Plan ${TIER_LABEL[q.tier]}`, 712);
  draw(q.nonprofit ? "Community / nonprofit discount applies" : "Community / nonprofit discount does not apply", 692);
  draw(q.pilot ? `Pilot in effect until ${q.pilotEndsAt?.toISOString().slice(0, 10) ?? ""}` : "No active pilot", 672);
  draw(`List price ex GST AUD ${aud(q.listCents)}`, 642);
  draw(`Discount ${q.discountBps} basis points`, 622);
  draw(`Amount ex GST AUD ${aud(q.exGstCents)}`, 592);
  draw(`GST 10% AUD ${aud(q.gstCents)}`, 572, 12, bold);
  draw(`Total inc GST AUD ${aud(q.incGstCents)}`, 552, 12, bold);
  draw("Indicative rate card. The Indigenous advisory group has not signed these prices off.", 500, 9);
  return pdf.save();
}
