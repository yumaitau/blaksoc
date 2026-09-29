import { PDFDocument, rgb, StandardFonts, type PDFFont, type PDFPage } from "pdf-lib";
import type { BoardLight, ReportContent, ReportSection } from "./types";

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
    for (const link of s.links ?? []) lines.push([q(link.label), q(link.href)].join(","));
    lines.push("");
  }
  return lines.join("\n");
}

/** WinAnsi-safe text for standard PDF fonts. */
const clean = (s: string) => s.replace(/[→–—]/g, "-").replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/[^\x09\x0A\x0D\x20-\x7E\xA0-\xFF]/g, "?");

const LIGHT: Record<BoardLight, { fill: [number, number, number]; ink: [number, number, number]; word: string }> = {
  steady: { fill: [0.85, 0.93, 0.86], ink: [0.02, 0.32, 0.18], word: "STEADY" },
  look: { fill: [0.99, 0.93, 0.75], ink: [0.35, 0.22, 0.02], word: "NEEDS A LOOK" },
  now: { fill: [0.98, 0.86, 0.84], ink: [0.45, 0.05, 0.05], word: "NEEDS ATTENTION NOW" },
};

type Draw = {
  pdf: PDFDocument;
  font: PDFFont;
  bold: PDFFont;
  page: PDFPage;
  y: number;
  W: number;
  H: number;
  M: number;
};

function wrap(text: string, f: PDFFont, size: number, width: number) {
  const out: string[] = [];
  for (const para of clean(text).split("\n")) {
    let line = "";
    for (const word of para.split(/\s+/)) {
      if (!word) continue;
      const next = line ? `${line} ${word}` : word;
      if (f.widthOfTextAtSize(next, size) > width && line) {
        out.push(line);
        line = word;
      } else line = next;
    }
    out.push(line);
  }
  return out;
}

export async function toPdf(title: string, content: ReportContent, layout: "document" | "slides" = "document"): Promise<Uint8Array> {
  return layout === "slides" ? slidesPdf(title, content) : documentPdf(title, content);
}

async function documentPdf(title: string, content: ReportContent): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const board = content.audience === "board";
  const W = 595, H = 842, M = 48;
  const bodySize = board ? 14 : 9.5;
  const headSize = board ? 18 : 12;
  const tagSize = board ? 11 : 7;
  const tableSize = board ? 11 : 8;
  const titleSize = board ? 24 : 18;
  const draw: Draw = { pdf, font, bold, page: pdf.addPage([W, H]), y: H - M, W, H, M };

  const newPage = () => {
    draw.page = pdf.addPage([W, H]);
    draw.y = H - M;
  };
  const text = (t: string, opts: { size?: number; f?: PDFFont; color?: [number, number, number]; indent?: number } = {}) => {
    const size = opts.size ?? 10;
    for (const l of wrap(t, opts.f ?? font, size, W - 2 * M - (opts.indent ?? 0))) {
      if (draw.y < M + size) newPage();
      draw.page.drawText(l, { x: M + (opts.indent ?? 0), y: draw.y, size, font: opts.f ?? font, color: rgb(...(opts.color ?? [0.1, 0.1, 0.1])) });
      draw.y -= size * 1.35;
    }
  };

  text("blakSOC", { size: board ? 12 : 9, f: bold, color: [0.55, 0.25, 0.1] });
  text(title, { size: titleSize, f: bold });
  text(`${content.tenantName} · ${content.period.start.slice(0, 10)} to ${content.period.end.slice(0, 10)} · generated ${content.generatedAt.slice(0, 16).replace("T", " ")} UTC`, { size: board ? 12 : 9, color: [0.4, 0.4, 0.4] });
  draw.y -= 6;
  text(board
    ? "Facts are marked as facts. Judgement is marked as judgement."
    : "Sections marked OBSERVED contain facts from telemetry and case records. Sections marked INTERPRETATION contain analyst or AI judgement.", { size: board ? 11 : 8, color: [0.4, 0.4, 0.4] });
  draw.y -= board ? 12 : 10;
  await paintImage(pdf, draw, content);
  paintLight(draw, content, board ? 16 : 12);

  for (const s of content.sections) {
    if (draw.y < M + 60) newPage();
    const tag = board
      ? (s.basis === "observed" ? "Facts" : "Judgement")
      : (s.basis === "observed" ? "OBSERVED" : `INTERPRETATION${s.author ? ` (${s.author.toUpperCase()})` : ""}`);
    text(tag, { size: tagSize, f: bold, color: s.basis === "observed" ? [0.1, 0.4, 0.3] : [0.6, 0.35, 0.05] });
    text(s.heading, { size: headSize, f: bold });
    if (s.body) text(s.body, { size: bodySize });
    for (const link of s.links ?? []) text(`${link.label}: ${link.href}`, { size: board ? 12 : 8, color: [0.15, 0.25, 0.45] });
    if (s.table) paintTable(draw, s, tableSize, newPage);
    draw.y -= board ? 14 : 10;
  }
  return pdf.save();
}

async function slidesPdf(title: string, content: ReportContent): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const W = 842, H = 595, M = 48;
  const open = (): Draw => {
    const page = pdf.addPage([W, H]);
    return { pdf, font, bold, page, y: H - M, W, H, M };
  };
  const draw = open();
  const nextPage = () => {
    draw.page = pdf.addPage([W, H]);
    draw.y = H - M;
  };
  const text = (t: string, opts: { size?: number; f?: PDFFont; color?: [number, number, number] } = {}) => {
    const size = opts.size ?? 18;
    for (const l of wrap(t, opts.f ?? font, size, W - 2 * M)) {
      if (draw.y < M + size) nextPage();
      draw.page.drawText(l, { x: M, y: draw.y, size, font: opts.f ?? font, color: rgb(...(opts.color ?? [0.1, 0.1, 0.1])) });
      draw.y -= size * 1.4;
    }
  };
  text("blakSOC", { size: 14, f: bold, color: [0.55, 0.25, 0.1] });
  text(title, { size: 32, f: bold });
  text(`${content.tenantName}. ${content.period.start.slice(0, 10)} to ${content.period.end.slice(0, 10)}.`, { size: 16, color: [0.25, 0.25, 0.25] });
  draw.y -= 8;
  await paintImage(pdf, draw, content);
  paintLight(draw, content, 22);
  for (const s of content.sections) {
    nextPage();
    const tag = s.basis === "observed" ? "Facts" : "Judgement";
    text(tag, { size: 14, f: bold, color: s.basis === "observed" ? [0.1, 0.4, 0.3] : [0.45, 0.25, 0.02] });
    text(s.heading, { size: 28, f: bold });
    draw.y -= 6;
    if (s.body) text(s.body, { size: 20 });
    for (const link of s.links ?? []) text(`${link.label}: ${link.href}`, { size: 14, color: [0.15, 0.25, 0.45] });
    if (s.table) paintTable(draw, s, 14, nextPage);
  }
  return pdf.save();
}

function paintLight(draw: Draw, content: ReportContent, size: number) {
  if (!content.light) return;
  const spec = LIGHT[content.light];
  const h = size + 16;
  if (draw.y - h < draw.M) return;
  draw.page.drawRectangle({ x: draw.M, y: draw.y - h + 8, width: draw.W - 2 * draw.M, height: h, color: rgb(...spec.fill) });
  draw.page.drawText(spec.word, { x: draw.M + 10, y: draw.y - size, size, font: draw.bold, color: rgb(...spec.ink) });
  draw.y -= h + 10;
}

async function paintImage(pdf: PDFDocument, draw: Draw, content: ReportContent) {
  if (!content.image?.data) return;
  try {
    const bytes = Buffer.from(content.image.data, "base64");
    const img = content.image.mime === "image/png" ? await pdf.embedPng(bytes) : await pdf.embedJpg(bytes);
    const maxW = 140;
    const scale = Math.min(1, maxW / img.width);
    const w = img.width * scale;
    const h = img.height * scale;
    if (draw.y - h < draw.M) return;
    draw.page.drawImage(img, { x: draw.M, y: draw.y - h, width: w, height: h });
    draw.y -= h + 10;
  } catch {
    // A stored image that is not a real PNG or JPEG is skipped. The words still print.
  }
}

function paintTable(draw: Draw, section: ReportSection, size: number, newPage: () => void) {
  const table = section.table;
  if (!table) return;
  const cols = table.columns.length || 1;
  const colW = (draw.W - 2 * draw.M) / cols;
  const line = size + 3;
  const drawRow = (cells: (string | number)[], f: PDFFont) => {
    const wrapped = cells.map((cell) => wrap(String(cell), f, size, colW - 6).slice(0, 4));
    const h = Math.max(1, ...wrapped.map((lines) => lines.length)) * line + 4;
    if (draw.y - h < draw.M) newPage();
    wrapped.forEach((lines, i) => lines.forEach((l, j) => draw.page.drawText(l, { x: draw.M + i * colW, y: draw.y - j * line, size, font: f })));
    draw.y -= h;
  };
  drawRow(table.columns, draw.bold);
  if (!table.rows.length) {
    draw.page.drawText("No records in period.", { x: draw.M, y: draw.y, size, font: draw.font, color: rgb(0.4, 0.4, 0.4) });
    draw.y -= line;
    return;
  }
  for (const row of table.rows) drawRow(row, draw.font);
}
