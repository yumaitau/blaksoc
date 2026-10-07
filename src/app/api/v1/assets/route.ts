import { json, serviceCall, shape } from "@/lib/api/http";
import { AssetList, AssetListQuery } from "@/lib/api/schemas";
import { listAssets } from "@/lib/services/assets";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  return serviceCall(req, "/assets", async (ctx) => {
    const q = AssetListQuery.parse(Object.fromEntries(new URL(req.url).searchParams));
    const rows = await listAssets(ctx, { tenantIds: q.tenantId ? [q.tenantId] : undefined, kind: q.kind, q: q.q, limit: q.limit });
    return json(200, shape(AssetList, { data: rows }));
  });
}
