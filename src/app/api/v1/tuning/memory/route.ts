import { json, jsonBody, requireScope, serviceCall, shape, tuningRate } from "@/lib/api/http";
import { HermesMemory, MemoryPut, MemoryPutResult } from "@/lib/api/schemas";
import { getMemory, putMemory } from "@/lib/services/hermes";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return serviceCall(req, "/tuning/memory", async (ctx) => {
    requireScope(ctx, "tuning:read");
    await tuningRate(ctx, "read");
    return json(200, shape(HermesMemory, await getMemory(ctx)));
  });
}

export async function PUT(req: Request) {
  return serviceCall(req, "/tuning/memory", async (ctx) => {
    requireScope(ctx, "tuning:memory");
    const input = MemoryPut.parse(await jsonBody(req, 4 * 1024 * 1024));
    await tuningRate(ctx, "memory");
    return json(200, shape(MemoryPutResult, await putMemory(ctx, input)));
  });
}
