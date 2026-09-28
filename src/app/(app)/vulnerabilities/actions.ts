"use server";
import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { setVulnStatus } from "@/lib/services/vulnerabilities";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function markVulns(ids: string[], status: "open" | "patched" | "accepted", note?: string) {
  if (!ids.length || ids.length > 500 || !ids.every((id) => UUID.test(id))) return { ok: false as const, error: "Select at least one instance." };
  if (!["open", "patched", "accepted"].includes(status)) return { ok: false as const, error: "Unknown status." };
  if (status === "accepted" && !note?.trim()) return { ok: false as const, error: "Record why the risk is being accepted." };
  const res = await withAccess((ctx) => setVulnStatus(ctx, ids, status, note?.trim().slice(0, 1000) || undefined));
  if (res.ok) {
    revalidatePath("/vulnerabilities");
    revalidatePath("/assets", "layout");
  }
  return res;
}
