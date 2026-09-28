import { PDFDocument, rgb, StandardFonts, type PDFFont, type PDFPage } from "pdf-lib";
import type { ReportContent } from "./types";

export function toCsv(content: ReportContent): string {
  const q = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const lines: string[] = [];
  for (const s of content.sections) {
    lines.push([q(`# ${s.heading}`), q(`basis=${s.basis}`), q(s.author ?? "")].join(","));
    if (s.table) {
      lines.push(s.table.columns.map(q).join(","));
      for (const r of s.table.rows) lines.push(r.map(q).join(","));
    }
    if (s.body) lines.push(q(s.body));
    lines.push("");
  }
  return lines.join("\n");
}

/** WinAnsi-safe text for standard PDF fonts. */
const clean = (s: string) => s.replace(/[→–—]/g, "-").replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[^\x09\x0A\x0D\x20-\x7E\xA0-\xFF]/g, "?");

export async function toPdf(title: string, content: ReportContent): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const W = 595, H = 842, M = 48;
  let page: PDFPage = pdf.addPage([W, H]);
  let y = H - M;

  const newPage = () => {
    page = pdf.addPage([W, H]);
    y = H - M;
  };
  const wrap = (text: string, f: PDFFont, size: number, width: number) => {
    const out: string[] = [];
    for (const para of clean(text).split("\n")) {
      let line = "";
      for (const word of para.split(/\s+/)) {
        const next = line ? `${line} ${word}` : word;
        if (f.widthOfTextAtSize(next, size) > width && line) {
          out.push(line);
          line = word;
        } else line = next;
      }
      out.push(line);
    }
    return out;
  };
  const text = (t: string, opts: { size?: number; f?: PDFFont; color?: [number, number, number]; indent?: number } = {}) => {
    const size = opts.size ?? 10;
    for (const l of wrap(t, opts.f ?? font, size, W - 2 * M - (opts.indent ?? 0))) {
      if (y < M + size) newPage();
      page.drawText(l, { x: M + (opts.indent ?? 0), y, size, font: opts.f ?? font, color: rgb(...(opts.color ?? [0.1, 0.1, 0.1])) });
      y -= size * 1.35;
    }
  };

  text("blakSOC", { size: 9, f: bold, color: [0.55, 0.25, 0.1] });
  text(title, { size: 18, f: bold });
  text(`${content.tenantName} · ${content.period.start.slice(0, 10)} to ${content.period.end.slice(0, 10)} · generated ${content.generatedAt.slice(0, 16).replace("T", " ")} UTC`, { size: 9, color: [0.4, 0.4, 0.4] });
  y -= 6;
  text("Sections marked OBSERVED contain facts from telemetry and case records. Sections marked INTERPRETATION contain analyst or AI judgement.", { size: 8, color: [0.4, 0.4, 0.4] });
  y -= 10;

  for (const s of content.sections) {
    if (y < M + 60) newPage();
    const tag = s.basis === "observed" ? "OBSERVED" : `INTERPRETATION${s.author ? ` (${s.author.toUpperCase()})` : ""}`;
    text(tag, { size: 7, f: bold, color: s.basis === "observed" ? [0.1, 0.4, 0.3] : [0.6, 0.35, 0.05] });
    text(s.heading, { size: 12, f: bold });
    if (s.body) text(s.body, { size: 9.5 });
    if (s.table) {
      const cols = s.table.columns.length;
      const colW = (W - 2 * M) / cols;
      const drawRow = (cells: (string | number)[], f: PDFFont) => {
        const wrapped = cells.map((c) => wrap(String(c), f, 8, colW - 6).slice(0, 4));
        const h = Math.max(...wrapped.map((w) => w.length)) * 10.5 + 4;
        if (y - h < M) newPage();
        wrapped.forEach((lines, i) => lines.forEach((l, j) => page.drawText(l, { x: M + i * colW, y: y - j * 10.5, size: 8, font: f })));
        y -= h;
      };
      drawRow(s.table.columns, bold);
      if (!s.table.rows.length) text("No records in period.", { size: 8, color: [0.5, 0.5, 0.5] });
      for (const r of s.table.rows) drawRow(r, font);
    }
    y -= 10;
  }
  return pdf.save();
}
