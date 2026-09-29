"use server";

import { revalidatePath } from "next/cache";
import { requireAccess } from "@/lib/auth/session";
import { completeExercise, saveIrPlan } from "@/lib/services/ir";

export async function savePlan(formData: FormData) {
  const ctx = await requireAccess();
  const tenantId = String(formData.get("tenantId") ?? "");
  await saveIrPlan(ctx, tenantId, {
    culturalProtocol: String(formData.get("culturalProtocol") ?? ""),
    bank: String(formData.get("bank") ?? ""),
    insurer: String(formData.get("insurer") ?? ""),
    itProvider: String(formData.get("itProvider") ?? ""),
  });
  revalidatePath("/portal/ir");
}

export async function finishExercise(formData: FormData) {
  const ctx = await requireAccess();
  const tenantId = String(formData.get("tenantId") ?? "");
  const scenarioId = String(formData.get("scenarioId") ?? "");
  await completeExercise(ctx, tenantId, scenarioId, {
    notes: String(formData.get("notes") ?? ""),
    lessons: String(formData.get("lessons") ?? ""),
  });
  revalidatePath("/portal/ir");
}
