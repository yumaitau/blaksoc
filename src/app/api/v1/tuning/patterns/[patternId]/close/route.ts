import { json, jsonBody, requireScope, serviceCall, shape, tuningRate } from "@/lib/api/http";
import { CloseRequest, CloseResult, PatternIdParam } from "@/lib/api/schemas";
import { closePattern } from "@/lib/services/hermes";

export const dynamic = "force-dynamic";

export async function POST(req: Request, { params }: { params: Promise<{ patternId: string }> }) {
  return serviceCall(req, "/tuning/patterns/{patternId}/close", async (ctx) => {
    requireScope(ctx, "tuning:act");
    const { patternId } = PatternIdParam.parse(await params);
    const input = CloseRequest.parse(await jsonBody(req, 8 * 1024));
    await tuningRate(ctx, "act");
    return json(200, shape(CloseResult, await closePattern(ctx, patternId, input)));
  });
}
