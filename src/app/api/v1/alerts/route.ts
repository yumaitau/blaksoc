import { json, serviceCall, shape } from "@/lib/api/http";
import { AlertList, AlertListQuery } from "@/lib/api/schemas";
import { listAlerts } from "@/lib/services/alerts";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return serviceCall(req, "/alerts", async (ctx) => {
    const q = AlertListQuery.parse(Object.fromEntries(new URL(req.url).searchParams));
    const { rows, total } = await listAlerts(ctx, {
      tenantIds: q.tenantId ? [q.tenantId] : undefined,
      status: q.status,
      severity: q.severity,
      sinceHours: q.sinceHours,
      lane: q.lane,
      limit: q.limit,
      offset: q.offset,
    });
    return json(200, shape(AlertList, { data: rows, total }));
  });
}
