"use server";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { withAccess } from "@/lib/actions";
import { decideApproval } from "@/lib/soar/response";

const decision = z
  .object({ approvalId: z.guid(), decision: z.enum(["APPROVED", "REJECTED"]), note: z.string().trim().max(2000) })
  .refine((d) => d.decision === "APPROVED" || d.note.length > 0, { message: "A note is required to reject", path: ["note"] });

export async function decide(input: z.input<typeof decision>) {
  return withAccess(async (ctx) => {
    const d = decision.parse(input);
    const ap = await decideApproval(ctx, d.approvalId, d.decision, d.note);
    revalidatePath("/soc/approvals");
    revalidatePath("/soc");
    return { status: ap.status };
  });
}
