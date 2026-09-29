"use server";

import { revalidatePath } from "next/cache";
import { requireAccess } from "@/lib/auth/session";
import { scheduleCampaign } from "@/lib/services/awareness";

export async function schedulePractice(formData: FormData) {
  const ctx = await requireAccess();
  const tenantId = String(formData.get("tenantId") ?? "");
  const consented = formData.get("consented") === "yes";
  const scheduledAt = new Date(String(formData.get("scheduledAt") ?? ""));
  await scheduleCampaign(ctx, tenantId, { consented, scheduledAt });
  revalidatePath("/portal/awareness");
}
