import { AccessDenied, can } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { auditCsv } from "@/lib/audit/csv";
import { parseAuditFilters } from "@/lib/audit/filters";
import { env } from "@/lib/env";
import { clientIpFromForwarded, parseTrustedProxies } from "@/lib/net/client-ip";
import { exportAuditTrail } from "@/lib/services/admin";

export const dynamic = "force-dynamic";

/**
 * CSV of the audit trail for the same filters as /admin/audit (the page cursor is ignored: the file
 * starts at the newest match). Needs audit:read, reads within the caller's audit scope, is capped
 * at AUDIT_EXPORT_CAP rows, and is itself recorded as "audit.export".
 */
export async function GET(req: Request) {
  const ctx = await currentAccess();
  if (!ctx) return new Response("Unauthorised", { status: 401 });
  if (!can(ctx, "audit:read")) return new Response("Forbidden", { status: 403 });

  const readable = ctx.tenants.filter((t) => can(ctx, "audit:read", t.id)).map((t) => t.id);
  const filters = parseAuditFilters(Object.fromEntries(new URL(req.url).searchParams), readable);
  const ip = clientIpFromForwarded(req.headers.get("x-forwarded-for"), parseTrustedProxies(env().TRUSTED_PROXY_CIDRS));
  try {
    const { rows, names, capped } = await exportAuditTrail(ctx, filters, ip);
    return new Response(auditCsv(rows, names), {
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": `attachment; filename="audit-trail-${new Date().toISOString().slice(0, 10)}.csv"`,
        "cache-control": "private, no-store",
        "x-audit-rows": String(rows.length),
        ...(capped ? { "x-audit-capped": "true" } : {}),
      },
    });
  } catch (err) {
    if (err instanceof AccessDenied) return new Response("Forbidden", { status: 403 });
    throw err;
  }
}
