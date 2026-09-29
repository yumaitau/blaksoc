import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { toCsv, toPdf } from "@/lib/reports/export";
import { getReport } from "@/lib/services/reports";

/** No report:read anywhere reads the same as "no such report". */
const denied = (err: unknown) => {
  if (err instanceof AccessDenied) return null;
  throw err;
};

/** Export a report the caller can read. Anything outside their tenant scope is a 404, never a 403. */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const ctx = await currentAccess();
  if (!ctx) return new Response("Unauthorised", { status: 401 });
  const { id } = await params;
  const format = new URL(req.url).searchParams.get("format") ?? "pdf";
  if (!["pdf", "csv", "json", "slides"].includes(format)) return new Response("format must be pdf, csv, json or slides", { status: 400 });
  const report = /^[0-9a-f-]{36}$/i.test(id) ? await getReport(ctx, id).catch(denied) : null;
  if (!report) return new Response("Not found", { status: 404 });

  const base = `${report.title}-${report.periodEnd.toISOString().slice(0, 10)}`.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const fileFormat = format === "slides" ? "pdf" : format;
  const headers = (type: string) => ({
    "content-type": type,
    "content-disposition": `attachment; filename="${base}${format === "slides" ? "-slides" : ""}.${fileFormat}"`,
    "cache-control": "private, no-store",
  });
  if (format === "pdf" || format === "slides") return new Response(Buffer.from(await toPdf(report.title, report.content, format === "slides" ? "slides" : "document")), { headers: headers("application/pdf") });
  if (format === "csv") return new Response(toCsv(report.content), { headers: headers("text/csv; charset=utf-8") });
  return new Response(JSON.stringify({ id: report.id, title: report.title, kind: report.kind, ...report.content }, null, 2), { headers: headers("application/json; charset=utf-8") });
}
