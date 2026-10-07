import { json, serviceCall, shape } from "@/lib/api/http";
import { IncidentList, IncidentListQuery } from "@/lib/api/schemas";
import { listIncidents } from "@/lib/services/incidents";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return serviceCall(req, "/incidents", async (ctx) => {
    const q = IncidentListQuery.parse(Object.fromEntries(new URL(req.url).searchParams));
    const rows = await listIncidents(ctx, { tenantIds: q.tenantId ? [q.tenantId] : undefined, status: q.status, open: q.open, limit: q.limit });
    return json(200, shape(IncidentList, { data: rows }));
  });
}
