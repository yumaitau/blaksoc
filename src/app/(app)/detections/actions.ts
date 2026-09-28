"use server";
import { revalidatePath } from "next/cache";
import { withAccess } from "@/lib/actions";
import { AccessDenied } from "@/lib/auth/access";
import { deployRule, getRule, saveRule, setRuleEnabled, testRule } from "@/lib/services/detections";

type TestCase = { name: string; event: Record<string, unknown>; expect: boolean };

/** New rule (tenantId chosen by the author) or a new version of an existing one (tenant taken from the stored rule). */
export async function saveRuleAction(input: { id?: string; tenantId: string | null; yaml: string; changeNote: string; confidence?: number }) {
  const r = await withAccess(async (ctx) => {
    let tenantId = input.tenantId;
    if (input.id) {
      const existing = await getRule(ctx, input.id);
      if (!existing) throw new AccessDenied("rule not found");
      tenantId = existing.rule.tenantId;
    }
    const confidence = input.confidence != null && Number.isFinite(input.confidence) ? Math.min(100, Math.max(0, Math.round(input.confidence))) : undefined;
    return saveRule(ctx, { id: input.id, tenantId, yaml: input.yaml, changeNote: input.changeNote.trim() || undefined, confidence });
  });
  if (r.ok) {
    revalidatePath("/detections");
    revalidatePath(`/detections/rules/${r.data!.id}`);
    revalidatePath("/detections/attack");
  }
  return r;
}

export async function setRuleEnabledAction(id: string, enabled: boolean) {
  const r = await withAccess(async (ctx) => {
    await setRuleEnabled(ctx, id, enabled);
  });
  revalidatePath("/detections");
  revalidatePath(`/detections/rules/${id}`);
  revalidatePath("/detections/attack");
  return r;
}

export async function testRuleAction(id: string, casesJson: string) {
  return withAccess(async (ctx) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(casesJson);
    } catch (e) {
      throw new Error(`Test cases are not valid JSON: ${(e as Error).message}`);
    }
    if (!Array.isArray(parsed) || !parsed.length) throw new Error("Test cases must be a non-empty JSON array of { name, event, expect }.");
    const cases: TestCase[] = parsed.map((c, i) => {
      if (!c || typeof c !== "object" || typeof c.event !== "object" || c.event === null || Array.isArray(c.event) || typeof c.expect !== "boolean")
        throw new Error(`Case ${i + 1}: expected { name: string, event: object, expect: boolean }.`);
      return { name: typeof c.name === "string" && c.name ? c.name : `case ${i + 1}`, event: c.event, expect: c.expect };
    });
    const res = await testRule(ctx, id, cases);
    revalidatePath(`/detections/rules/${id}`);
    return res;
  });
}

export async function deployRuleAction(id: string, tenantIds: string[]) {
  const r = await withAccess(async (ctx) => {
    if (!tenantIds.length) throw new Error("Select at least one customer.");
    return deployRule(ctx, id, tenantIds);
  });
  revalidatePath(`/detections/rules/${id}`);
  revalidatePath("/detections");
  revalidatePath("/detections/attack");
  return r;
}
