import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import type { Answer, Applicability, BreachDecision, DraftKind, ReferralKey } from "@/lib/obligations/model";
import { ObligationError, createDraft, recordDecision, recordHarm, recordReferral, setLegalReview, startObligation } from "@/lib/services/obligations";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

export async function POST(req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const back = `/portal/incidents/${id}`;
  const access = await currentAccess();
  if (!access) return go("/login");
  const form = await req.formData();
  const intent = String(form.get("intent") ?? "");
  try {
    if (intent === "start") {
      const startedAt = new Date(`${String(form.get("startedAt") ?? "")}T00:00:00.000Z`);
      const applicability: Applicability = {
        privacyAct: String(form.get("privacyAct") ?? "") as Answer,
        healthInformation: String(form.get("healthInformation") ?? "") as Answer,
        governmentContract: String(form.get("governmentContract") ?? "") as Answer,
        soci: String(form.get("soci") ?? "") as Answer,
      };
      await startObligation(access, id, { startedAt, applicability, insurerPolicy: String(form.get("insurerPolicy") ?? "") });
    } else if (intent === "harm") {
      await recordHarm(access, id, { seriousHarm: String(form.get("seriousHarm") ?? "") as Answer, rationale: String(form.get("rationale") ?? "") });
    } else if (intent === "decision") {
      await recordDecision(access, id, { decision: String(form.get("decision") ?? "") as BreachDecision, rationale: String(form.get("rationale") ?? "") });
    } else if (intent === "referral") {
      await recordReferral(access, id, { key: String(form.get("key") ?? "") as ReferralKey, policyNumber: String(form.get("policyNumber") ?? "") });
    } else if (intent === "draft") {
      await createDraft(access, id, String(form.get("kind") ?? "") as DraftKind);
    } else if (intent === "legal") {
      await setLegalReview(access, id, String(form.get("requested") ?? "") === "yes");
    } else {
      return go(`${back}?error=generic`);
    }
    return go(back);
  } catch (err) {
    if (err instanceof ObligationError) return go(`${back}?error=${err.code}`);
    if (err instanceof AccessDenied) return go(`${back}?error=generic`);
    return go(`${back}?error=generic`);
  }
}
