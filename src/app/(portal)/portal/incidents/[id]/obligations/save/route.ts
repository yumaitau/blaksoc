import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { zonedTime, type ClockKind } from "@/lib/obligations/clock";
import type { Answer, Applicability, BreachDecision, DraftKind, ReferralKey } from "@/lib/obligations/model";
import {
  ObligationError, createDraft, markClockReported, recordDecision, recordHarm, recordReferral, setLegalReview, startClock, startObligation, updateApplicability,
} from "@/lib/services/obligations";

function applicabilityOf(form: FormData): Applicability {
  const answer = (key: keyof Applicability) => String(form.get(key) ?? "") as Answer;
  return {
    privacyAct: answer("privacyAct"),
    healthInformation: answer("healthInformation"),
    governmentContract: answer("governmentContract"),
    soci: answer("soci"),
    ransomwareReporting: answer("ransomwareReporting"),
  };
}

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
      await startObligation(access, id, { startedAt, applicability: applicabilityOf(form), insurerPolicy: String(form.get("insurerPolicy") ?? "") });
    } else if (intent === "applicability") {
      await updateApplicability(access, id, applicabilityOf(form));
    } else if (intent === "clock") {
      const timeZone = String(form.get("timeZone") ?? "");
      await startClock(access, id, { kind: String(form.get("kind") ?? "") as ClockKind, startedAt: zonedTime(String(form.get("startedAt") ?? ""), timeZone), timeZone });
    } else if (intent === "reported") {
      await markClockReported(access, id, { kind: String(form.get("kind") ?? "") as ClockKind, reference: String(form.get("reference") ?? "") });
    } else if (intent === "harm") {
      await recordHarm(access, id, { seriousHarm: String(form.get("seriousHarm") ?? "") as Answer, rationale: String(form.get("rationale") ?? "") });
    } else if (intent === "decision") {
      await recordDecision(access, id, { decision: String(form.get("decision") ?? "") as BreachDecision, rationale: String(form.get("rationale") ?? "") });
    } else if (intent === "referral") {
      await recordReferral(access, id, { key: String(form.get("key") ?? "") as ReferralKey, policyNumber: String(form.get("policyNumber") ?? "") });
    } else if (intent === "draft") {
      await createDraft(access, id, String(form.get("kind") ?? "") as DraftKind | ClockKind);
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
