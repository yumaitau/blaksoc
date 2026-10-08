import { json, requireScope, serviceCall, shape, tuningRate } from "@/lib/api/http";
import { TuningActionList, TuningActionsQuery } from "@/lib/api/schemas";
import { listAgentActions } from "@/lib/services/hermes";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return serviceCall(req, "/tuning/actions", async (ctx) => {
    requireScope(ctx, "tuning:read");
    const q = TuningActionsQuery.parse(Object.fromEntries(new URL(req.url).searchParams));
    await tuningRate(ctx, "read");
    const since = q.since ? new Date(q.since) : new Date(Date.now() - 7 * 86_400_000);
    return json(200, shape(TuningActionList, { actions: await listAgentActions(ctx, since) }));
  });
}
