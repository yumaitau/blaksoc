"use server";
import { revalidatePath } from "next/cache";
import { ZodError } from "zod";
import { withAccess } from "@/lib/actions";
import { createIntegration, linkTenant, setAlertFloor, testIntegration, updateIntegration } from "@/lib/services/integrations";
import type { Severity } from "@/lib/providers/types";

/** Zod issues name the field and rule only, never the submitted value, so they are safe to show. */
async function explain<T>(p: Promise<T>): Promise<T> {
  try {
    return await p;
  } catch (err) {
    if (err instanceof ZodError) throw new Error(`Invalid settings: ${err.issues.map((i) => `${i.path.join(".") || "value"}: ${i.message}`).join("; ")}`);
    throw err;
  }
}

const refresh = (id?: string) => {
  revalidatePath("/integrations");
  if (id) revalidatePath(`/integrations/${id}`);
};

export async function createIntegrationAction(input: { tenantId: string | null; provider: string; name: string; config: unknown; secrets: Record<string, string> }) {
  return withAccess(async (ctx) => {
    const secrets = Object.fromEntries(Object.entries(input.secrets).filter(([, v]) => v));
    const id = await explain(createIntegration(ctx, { ...input, name: input.name.trim(), secrets }));
    refresh();
    return id;
  });
}

export async function updateIntegrationAction(id: string, input: { name?: string; config?: unknown; secrets?: Record<string, string>; enabled?: boolean }) {
  return withAccess(async (ctx) => {
    await explain(updateIntegration(ctx, id, input));
    refresh(id);
  });
}

export async function testIntegrationAction(id: string) {
  return withAccess(async (ctx) => {
    const health = await testIntegration(ctx, id);
    refresh(id);
    return { ok: health.ok, latencyMs: health.latencyMs, error: health.error };
  });
}

export async function linkTenantAction(id: string, tenantId: string, agentGroups: string[]) {
  return withAccess(async (ctx) => {
    await linkTenant(ctx, id, tenantId, { agentGroups: agentGroups.map((g) => g.trim()).filter(Boolean) });
    refresh(id);
  });
}

export async function setAlertFloorAction(id: string, severity: Severity) {
  return withAccess(async (ctx) => {
    await explain(setAlertFloor(ctx, id, severity));
    refresh(id);
  });
}
