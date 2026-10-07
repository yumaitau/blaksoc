import { idParam, json, NotFound, serviceCall, shape } from "@/lib/api/http";
import { Alert } from "@/lib/api/schemas";
import { getAlert } from "@/lib/services/alerts";

export const dynamic = "force-dynamic";

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  return serviceCall(req, "/alerts/{id}", async (ctx) => {
    const a = await getAlert(ctx, idParam((await params).id));
    if (!a) throw new NotFound();
    return json(200, shape(Alert, { ...a.alert, tenantName: a.tenantName, observables: a.observables }));
  });
}
