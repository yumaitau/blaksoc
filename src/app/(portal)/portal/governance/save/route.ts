import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { decideGovernanceChange, GovernanceError, proposeGovernanceChange } from "@/lib/services/governance";
import { currentWorkspace } from "@/lib/workspace";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

export async function POST(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  const ws = await currentWorkspace(access);
  const tenant = ws.tenant ?? access.tenants.find((item) => item.kind === "customer");
  if (!tenant) return go("/portal/governance?error=denied");
  const form = await req.formData();
  const intent = String(form.get("intent") ?? "");
  let result = "saved";
  try {
    if (intent === "propose") {
      const share = String(form.get("sightings") ?? "none");
      const change = await proposeGovernanceChange(access, tenant.id, {
        residencyLock: form.get("residencyLock") === "on",
        sightings: share === "anonymised" || share === "named" ? { attribution: share, maxTlp: String(form.get("maxTlp") ?? "TLP:GREEN") } : null,
        ai: { assistant: form.get("aiAssistant") === "on", triage_summary: form.get("aiTriage") === "on" },
      }, String(form.get("reason") ?? ""));
      result = change.status === "applied" ? "applied" : "waiting";
    } else if (intent === "approve" || intent === "reject") {
      const out = await decideGovernanceChange(access, String(form.get("changeId") ?? ""), intent);
      result = out.status === "pending" ? "waiting" : out.status;
    } else {
      return go("/portal/governance?error=generic");
    }
  } catch (err) {
    if (err instanceof AccessDenied) return go("/portal/governance?error=denied");
    if (err instanceof GovernanceError) return go(`/portal/governance?error=${err.code}`);
    return go("/portal/governance?error=generic");
  }
  return go(`/portal/governance?ok=${result}`);
}
