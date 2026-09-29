import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { quoteCsv, quotePdf, readSupplierAbn } from "@/lib/billing/invoice";
import { quoteFor } from "@/lib/services/billing";

const denied = (err: unknown) => {
  if (err instanceof AccessDenied) return null;
  throw err;
};

/** Quote or invoice for a customer the caller can see. Missing ABN is 503, never a made-up number. */
export async function GET(req: Request, { params }: { params: Promise<{ tenantId: string }> }) {
  const ctx = await currentAccess();
  if (!ctx) return new Response("Unauthorised", { status: 401 });
  const { tenantId } = await params;
  if (!/^[0-9a-f-]{36}$/i.test(tenantId)) return new Response("Not found", { status: 404 });
  const format = new URL(req.url).searchParams.get("format") ?? "pdf";
  if (format !== "pdf" && format !== "csv") return new Response("format must be pdf or csv", { status: 400 });
  if (!readSupplierAbn()) {
    return new Response("Set BLAKSOC_SUPPLIER_ABN to the supplier 11-digit ABN before exporting a quote.", { status: 503 });
  }
  const quote = await quoteFor(ctx, tenantId).catch(denied);
  if (!quote || "error" in quote) return new Response("Not found", { status: 404 });

  const base = `quote-${quote.customerName}`.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "quote";
  const headers = (type: string, ext: string) => ({
    "content-type": type,
    "content-disposition": `attachment; filename="${base}.${ext}"`,
    "cache-control": "private, no-store",
  });
  if (format === "csv") return new Response(quoteCsv(quote), { headers: headers("text/csv; charset=utf-8", "csv") });
  return new Response(Buffer.from(await quotePdf(quote)), { headers: headers("application/pdf", "pdf") });
}
