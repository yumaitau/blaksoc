import { json, jsonBody, requireScope, serviceCall, shape, tuningRate } from "@/lib/api/http";
import { AgentNoiseRuleCreate, AgentNoiseRuleResult } from "@/lib/api/schemas";
import { createAgentNoiseRule } from "@/lib/services/hermes";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  return serviceCall(req, "/tuning/noise-rules", async (ctx) => {
    requireScope(ctx, "tuning:act");
    const input = AgentNoiseRuleCreate.parse(await jsonBody(req, 8 * 1024));
    await tuningRate(ctx, "act");
    return json(201, shape(AgentNoiseRuleResult, await createAgentNoiseRule(ctx, input)));
  });
}
