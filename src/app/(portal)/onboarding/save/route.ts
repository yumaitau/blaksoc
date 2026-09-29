import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { ONBOARDING_STEPS, type OnboardingStep } from "@/lib/onboarding/types";
import { canRunOnboarding, finishOnboarding, OnboardingError, saveOnboardingStep, startOnboarding } from "@/lib/services/onboarding";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

function rawFrom(form: FormData): Record<string, unknown> {
  const raw: Record<string, unknown> = {};
  for (const key of new Set(form.keys())) {
    const all = form.getAll(key).filter((item): item is string => typeof item === "string");
    raw[key] = all.length > 1 ? all : (all[0] ?? "");
  }
  return raw;
}

export async function POST(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  if (!canRunOnboarding(access)) return go("/onboarding?error=analyst");
  const form = await req.formData();
  const step = String(form.get("step") ?? "");
  try {
    if (step === "start") {
      await startOnboarding(access);
      return go("/onboarding");
    }
    if (!ONBOARDING_STEPS.includes(step as OnboardingStep)) return go("/onboarding?error=generic");
    const draftId = String(form.get("draftId") ?? "");
    await saveOnboardingStep(access, draftId, step as OnboardingStep, rawFrom(form));
    if (step === "plan" && form.get("finish") === "yes") await finishOnboarding(access, draftId);
    return go("/onboarding");
  } catch (err) {
    if (err instanceof OnboardingError) return go(`/onboarding?error=${err.code}`);
    if (err instanceof AccessDenied) return go(err.message === "draft" ? "/onboarding?error=owner" : "/onboarding?error=denied");
    return go("/onboarding?error=generic");
  }
}
