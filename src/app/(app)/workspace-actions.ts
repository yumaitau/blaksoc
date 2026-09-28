"use server";
import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { currentAccess } from "@/lib/auth/session";
import { WORKSPACE_COOKIE } from "@/lib/workspace";

export async function setWorkspace(tenantId: string) {
  const ctx = await currentAccess();
  if (!ctx) return;
  // Only tenants the caller can reach are accepted; anything else resets to "all".
  const value = tenantId !== "all" && ctx.tenantIds.includes(tenantId) ? tenantId : "all";
  (await cookies()).set(WORKSPACE_COOKIE, value, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" });
  revalidatePath("/", "layout");
}
