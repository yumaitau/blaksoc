"use server";

import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { cosignTrainee, TrainingError } from "@/lib/services/training";

export async function cosign(formData: FormData) {
  return withAccess(async (ctx) => {
    const tenantId = String(formData.get("tenantId") ?? "");
    const traineeId = String(formData.get("traineeId") ?? "");
    try {
      await cosignTrainee(ctx, tenantId, traineeId);
    } catch (err) {
      if (err instanceof TrainingError && err.code === "tenant") throw new Error("Training is not switched on for this room.");
      if (err instanceof TrainingError && err.code === "attempt") throw new Error("This trainee has no attempts to co-sign yet.");
      throw err;
    }
    revalidatePath("/soc/training");
  });
}
