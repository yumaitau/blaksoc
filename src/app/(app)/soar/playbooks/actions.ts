"use server";
import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { runPlaybookManually, savePlaybook, setPlaybookEnabled, type PlaybookInput } from "@/lib/services/playbooks";

export async function savePlaybookAction(input: PlaybookInput) {
  return withAccess(async (ctx) => {
    const id = await savePlaybook(ctx, input);
    revalidatePath("/soar/playbooks");
    revalidatePath(`/soar/playbooks/${id}`);
    return id;
  });
}

export async function setPlaybookEnabledAction(id: string, enabled: boolean) {
  return withAccess(async (ctx) => {
    await setPlaybookEnabled(ctx, id, enabled);
    revalidatePath("/soar/playbooks");
    revalidatePath(`/soar/playbooks/${id}`);
  });
}

export async function runPlaybookAction(playbookId: string, alertId: string) {
  return withAccess(async (ctx) => {
    const runId = await runPlaybookManually(ctx, playbookId, { alertId });
    revalidatePath(`/soar/playbooks/${playbookId}`);
    revalidatePath("/soar/runs");
    return runId;
  });
}
