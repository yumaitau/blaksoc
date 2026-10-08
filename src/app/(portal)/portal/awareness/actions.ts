"use server";

import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { AwarenessError, scheduleCampaign } from "@/lib/services/awareness";

const EXPLAIN: Partial<Record<AwarenessError["code"], string>> = {
  consent: "Tick the consent box to schedule a practice send.",
  schedule: "Choose a date and time for the practice send.",
};

export async function schedulePractice(formData: FormData) {
  return withAccess(async (ctx) => {
    const tenantId = String(formData.get("tenantId") ?? "");
    const consented = formData.get("consented") === "yes";
    const scheduledAt = new Date(String(formData.get("scheduledAt") ?? ""));
    try {
      await scheduleCampaign(ctx, tenantId, { consented, scheduledAt });
    } catch (err) {
      if (err instanceof AwarenessError && EXPLAIN[err.code]) throw new Error(EXPLAIN[err.code]);
      throw err;
    }
    revalidatePath("/portal/awareness");
  });
}
