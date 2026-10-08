import { json, jsonBody, requireScope, serviceCall, shape, tuningRate } from "@/lib/api/http";
import { AnnotationCreate, AnnotationResult, PatternIdParam } from "@/lib/api/schemas";
import { annotatePattern } from "@/lib/services/hermes";

export const dynamic = "force-dynamic";

export async function POST(req: Request, { params }: { params: Promise<{ patternId: string }> }) {
  return serviceCall(req, "/tuning/patterns/{patternId}/annotations", async (ctx) => {
    requireScope(ctx, "tuning:annotate");
    const { patternId } = PatternIdParam.parse(await params);
    const input = AnnotationCreate.parse(await jsonBody(req, 16 * 1024));
    await tuningRate(ctx, "annotate");
    return json(201, shape(AnnotationResult, await annotatePattern(ctx, patternId, input)));
  });
}
