import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { EssentialEightError, submitEssentialEight } from "@/lib/services/essential-eight";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

export async function POST(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  const form = await req.formData();
  const tenantId = String(form.get("tenantId") ?? "");
  const answers: Record<string, string> = {};
  for (const [key, value] of form.entries()) {
    if (typeof value === "string") answers[key] = value;
  }
  const cadence = Number(form.get("cadenceDays"));
  try {
    await submitEssentialEight(access, tenantId, { answers, owner: String(form.get("owner") ?? ""), cadenceDays: cadence });
    return go("/portal/essential-eight");
  } catch (err) {
    if (err instanceof EssentialEightError) return go(`/portal/essential-eight?error=${err.code === "missing" ? "generic" : err.code}`);
    if (err instanceof AccessDenied) return go("/portal/essential-eight?error=denied");
    return go("/portal/essential-eight?error=generic");
  }
}
