"use server";

import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { writeDashboardLayout } from "@/lib/services/dashboard-layout";

export async function saveDashboardLayout(widgets: unknown) {
  return withAccess(async (ctx) => {
    await writeDashboardLayout(ctx, widgets);
    revalidatePath("/soc");
  });
}
