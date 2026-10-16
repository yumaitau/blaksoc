"use server";
import { withAccess, type ActionResult } from "@/lib/actions";
import { quickSearch, type QuickHit } from "@/lib/services/quick-search";
import { currentWorkspace } from "@/lib/workspace";

/** Command palette lookup, within the selected workspace. */
export async function paletteSearch(q: string): Promise<ActionResult<QuickHit[]>> {
  return withAccess(async (ctx) => quickSearch(ctx, q, (await currentWorkspace(ctx)).tenantIds));
}
