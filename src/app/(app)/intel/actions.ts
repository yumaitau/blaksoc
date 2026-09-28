"use server";
import { revalidatePath } from "next/cache";
import type { SectorTag } from "@/db/schema";
import { withAccess } from "@/lib/actions";
import { requestSighting, setFeedEnabled, setFeedEntitlement, tagIntel } from "@/lib/services/intel";

export async function tagIntelAction(input: { openctiId: string; entityType: string; name: string; tags: SectorTag[] }) {
  const r = await withAccess((ctx) => tagIntel(ctx, input));
  revalidatePath("/intel");
  return r;
}

export async function requestSightingAction(matchId: string) {
  const r = await withAccess((ctx) => requestSighting(ctx, matchId));
  revalidatePath("/intel");
  return r;
}

export async function setFeedEnabledAction(key: string, enabled: boolean) {
  const r = await withAccess((ctx) => setFeedEnabled(ctx, key, enabled));
  revalidatePath("/intel");
  return r;
}

export async function setFeedEntitlementAction(key: string, tenantId: string, allowed: boolean) {
  const r = await withAccess((ctx) => setFeedEntitlement(ctx, key, tenantId, allowed));
  revalidatePath("/intel");
  return r;
}
