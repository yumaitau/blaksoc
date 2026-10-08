"use server";

import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { completeExercise, IrError, saveIrPlan } from "@/lib/services/ir";

export async function savePlan(formData: FormData) {
  return withAccess(async (ctx) => {
    const tenantId = String(formData.get("tenantId") ?? "");
    await saveIrPlan(ctx, tenantId, {
      culturalProtocol: String(formData.get("culturalProtocol") ?? ""),
      bank: String(formData.get("bank") ?? ""),
      insurer: String(formData.get("insurer") ?? ""),
      itProvider: String(formData.get("itProvider") ?? ""),
    });
    revalidatePath("/portal/ir");
  });
}

export async function finishExercise(formData: FormData) {
  return withAccess(async (ctx) => {
    const tenantId = String(formData.get("tenantId") ?? "");
    const scenarioId = String(formData.get("scenarioId") ?? "");
    try {
      await completeExercise(ctx, tenantId, scenarioId, {
        notes: String(formData.get("notes") ?? ""),
        lessons: String(formData.get("lessons") ?? ""),
      });
    } catch (err) {
      if (err instanceof IrError && err.code === "scenario") throw new Error("That exercise is not available any more. Reload the page.");
      throw err;
    }
    revalidatePath("/portal/ir");
  });
}
