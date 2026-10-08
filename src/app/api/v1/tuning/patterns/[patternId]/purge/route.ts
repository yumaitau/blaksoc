import { json, requireScope, serviceCall, shape, tuningRate } from "@/lib/api/http";
import { PatternIdParam, PurgeResult } from "@/lib/api/schemas";
import { purgePattern } from "@/lib/services/hermes";

export const dynamic = "force-dynamic";

export async function POST(req: Request, { params }: { params: Promise<{ patternId: string }> }) {
  return serviceCall(req, "/tuning/patterns/{patternId}/purge", async (ctx) => {
    requireScope(ctx, "tuning:act");
    const { patternId } = PatternIdParam.parse(await params);
    await tuningRate(ctx, "act");
    return json(200, shape(PurgeResult, await purgePattern(ctx, patternId)));
  });
}
