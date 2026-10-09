"use server";

import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { createWallboardLink, revokeWallboardLink } from "@/lib/services/wallboard";
import type { WallboardExpiryDays } from "@/lib/wallboard/types";

export async function createWallboardLinkAction(input: { name: string; tenantIds: string[]; expiresInDays: WallboardExpiryDays }) {
  return withAccess(async (ctx) => {
    const issued = await createWallboardLink(ctx, input);
    revalidatePath("/soc/wallboard");
    return issued;
  });
}

export async function revokeWallboardLinkAction(id: string) {
  return withAccess(async (ctx) => {
    await revokeWallboardLink(ctx, id);
    revalidatePath("/soc/wallboard");
  });
}
