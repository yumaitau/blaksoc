import { idParam, json, NotFound, serviceCall, shape } from "@/lib/api/http";
import { Incident } from "@/lib/api/schemas";
import { getIncident } from "@/lib/services/incidents";

export const dynamic = "force-dynamic";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  return serviceCall(req, "/incidents/{id}", async (ctx) => {
    const r = await getIncident(ctx, idParam((await params).id));
    if (!r) throw new NotFound();
    return json(200, shape(Incident, { ...r.incident, tenantName: r.tenantName, ownerName: r.ownerName, alerts: r.alerts, notes: r.notes }));
  });
}
