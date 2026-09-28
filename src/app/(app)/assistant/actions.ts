"use server";
import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { runAssistant } from "@/lib/ai/assistant";

export async function askAssistant(input: { tenantId: string; message: string; conversationId?: string; subject?: { type: "alert" | "incident"; id: string }; allowWrites: boolean }) {
  return withAccess(async (ctx) => {
    const message = input.message.trim();
    if (!message) throw new Error("Type a question first.");
    if (message.length > 4000) throw new Error("Keep questions under 4,000 characters.");
    const subject = input.subject && ["alert", "incident"].includes(input.subject.type) && /^[0-9a-f-]{36}$/i.test(input.subject.id) ? input.subject : undefined;
    const reply = await runAssistant(ctx, { tenantId: input.tenantId, message, conversationId: input.conversationId, subject, allowWrites: input.allowWrites === true });
    revalidatePath("/assistant");
    return reply;
  });
}
