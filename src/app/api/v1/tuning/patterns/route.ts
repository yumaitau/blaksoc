import { json, requireScope, serviceCall, shape, tuningRate } from "@/lib/api/http";
import { TuningPatternList, TuningPatternsQuery } from "@/lib/api/schemas";
import { listPatterns } from "@/lib/services/hermes";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return serviceCall(req, "/tuning/patterns", async (ctx) => {
    requireScope(ctx, "tuning:read");
    const q = TuningPatternsQuery.parse(Object.fromEntries(new URL(req.url).searchParams));
    await tuningRate(ctx, "read");
    return json(200, shape(TuningPatternList, await listPatterns(ctx, q.days)));
  });
}
