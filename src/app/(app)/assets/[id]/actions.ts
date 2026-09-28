"use server";
import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { updateAsset } from "@/lib/services/assets";
import { EXPOSURES } from "../asset-bits";

export async function saveAssetContext(id: string, input: { criticality: number; exposure: string; owner: string; privileged?: boolean }) {
  const criticality = Math.trunc(Number(input.criticality));
  if (!(criticality >= 1 && criticality <= 5)) return { ok: false as const, error: "Criticality must be between 1 and 5." };
  if (!(EXPOSURES as readonly string[]).includes(input.exposure)) return { ok: false as const, error: "Choose a valid exposure." };
  const owner = input.owner.trim().slice(0, 200) || null;
  const res = await withAccess((ctx) =>
    updateAsset(ctx, id, { criticality, exposure: input.exposure, owner, ...(input.privileged != null ? { privileged: input.privileged } : {}) }).then(() => undefined),
  );
  if (res.ok) {
    revalidatePath(`/assets/${id}`);
    revalidatePath("/assets");
  }
  return res;
}
