import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { canRunOnboarding, OnboardingError, recordM365Consent } from "@/lib/services/onboarding";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

/** Microsoft redirects here after the admin agrees or declines. */
export async function GET(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  if (!canRunOnboarding(access)) return go("/onboarding?error=analyst");
  try {
    await recordM365Consent(access, new URL(req.url).searchParams);
    return go("/onboarding?step=connect");
  } catch (err) {
    if (err instanceof OnboardingError) return go(`/onboarding?error=${err.code}&step=connect`);
    if (err instanceof AccessDenied) return go("/onboarding?error=owner");
    return go("/onboarding?error=consent&step=connect");
  }
}
