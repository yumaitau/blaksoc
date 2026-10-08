"use server";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { withAccess } from "@/lib/actions";
import { addHumanNote, deleteMemoryNote } from "@/lib/services/hermes";
import { approveNoiseRule, expireNoiseRule, extendNoiseRule, rejectNoiseRule, setHermesMayAct, undoTuningAction } from "@/lib/services/tuning";

const id = z.guid();

function refresh() {
  revalidatePath("/soc/tuning");
  revalidatePath("/soc/hermes");
  revalidatePath("/soc/alerts");
}

export async function approveRule(ruleId: string) {
  return withAccess(async (ctx) => {
    const res = await approveNoiseRule(ctx, id.parse(ruleId));
    refresh();
    return res;
  });
}

export async function rejectRule(ruleId: string) {
  return withAccess(async (ctx) => {
    await rejectNoiseRule(ctx, id.parse(ruleId));
    refresh();
  });
}

export async function expireRule(ruleId: string) {
  return withAccess(async (ctx) => {
    await expireNoiseRule(ctx, id.parse(ruleId));
    refresh();
  });
}

export async function extendRule(ruleId: string, days: number) {
  return withAccess(async (ctx) => {
    const res = await extendNoiseRule(ctx, id.parse(ruleId), z.number().int().min(1).max(180).parse(days));
    refresh();
    return res;
  });
}

export async function undoAction(actionId: string) {
  return withAccess(async (ctx) => {
    const res = await undoTuningAction(ctx, id.parse(actionId));
    refresh();
    return res;
  });
}

export async function setHermesSwitch(enabled: boolean) {
  return withAccess(async (ctx) => {
    await setHermesMayAct(ctx, z.boolean().parse(enabled));
    refresh();
  });
}

const noteInput = z.object({ text: z.string().trim().min(1).max(2000) });

export async function addMemoryNote(input: z.input<typeof noteInput>) {
  return withAccess(async (ctx) => {
    const v = noteInput.parse(input);
    const res = await addHumanNote(ctx, { text: v.text });
    refresh();
    return res;
  });
}

export async function removeMemoryNote(noteId: string) {
  return withAccess(async (ctx) => {
    const res = await deleteMemoryNote(ctx, id.parse(noteId));
    refresh();
    return res;
  });
}
