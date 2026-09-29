"use server";

import { revalidatePath } from "next/cache";
import { requireAccess } from "@/lib/auth/session";
import { cosignTrainee } from "@/lib/services/training";

export async function cosign(formData: FormData) {
  const ctx = await requireAccess();
  const tenantId = String(formData.get("tenantId") ?? "");
  const traineeId = String(formData.get("traineeId") ?? "");
  await cosignTrainee(ctx, tenantId, traineeId);
  revalidatePath("/soc/training");
}
