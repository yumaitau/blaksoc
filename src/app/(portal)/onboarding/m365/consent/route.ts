import { NextResponse } from "next/server";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { adminConsentUrl, consentConfigured, signState } from "@/lib/onboarding/m365-consent";
import { canRunOnboarding, getDraft } from "@/lib/services/onboarding";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

/** Sends the customer's Microsoft 365 admin to the consent page for the blakSOC connector app. */
export async function GET(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  if (!canRunOnboarding(access)) return go("/onboarding?error=analyst");
  if (!consentConfigured()) return go("/onboarding?error=consent");
  const draftId = new URL(req.url).searchParams.get("draft") ?? "";
  try {
    const draft = await getDraft(access, draftId);
    if (draft.status === "complete") return go("/onboarding");
    return NextResponse.redirect(adminConsentUrl(signState(draft.id, access.principal.userId)), 303);
  } catch {
    return go("/onboarding?error=owner");
  }
}
