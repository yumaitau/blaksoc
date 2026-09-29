import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { addDomains, attestDomain, checkPostureForm, confirmVerification, ingestDmarc, recordExposures, SurfaceError } from "@/lib/services/surface";
import { currentWorkspace } from "@/lib/workspace";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

export async function POST(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  const ws = await currentWorkspace(access);
  const tenant = ws.tenant ?? access.tenants.find((item) => item.kind === "customer");
  if (!tenant) return go("/portal/domains?error=denied");
  const form = await req.formData();
  const intent = String(form.get("intent") ?? "");
  try {
    if (intent === "add") {
      await addDomains(access, tenant.id, String(form.get("name") ?? ""));
    } else if (intent === "verify") {
      const txt = String(form.get("txt") ?? "").split(/\n+/).map((line) => line.trim()).filter(Boolean);
      await confirmVerification(access, tenant.id, String(form.get("domainId") ?? ""), txt);
    } else if (intent === "check") {
      await checkPostureForm(access, tenant.id, String(form.get("domainId") ?? ""), {
        spf: String(form.get("spf") ?? ""),
        dmarc: String(form.get("dmarc") ?? ""),
        dkim: String(form.get("dkim") ?? ""),
        extras: String(form.get("extras") ?? ""),
      });
    } else if (intent === "attest") {
      await attestDomain(access, tenant.id, String(form.get("domainId") ?? ""));
    } else if (intent === "exposure") {
      await recordExposures(access, tenant.id, String(form.get("domainId") ?? ""));
    } else if (intent === "dmarc") {
      const file = form.get("file");
      if (!(file instanceof File)) return go("/portal/domains?error=generic");
      await ingestDmarc(access, tenant.id, file.name, Buffer.from(await file.arrayBuffer()));
    } else {
      return go("/portal/domains?error=generic");
    }
  } catch (err) {
    if (err instanceof AccessDenied) return go("/portal/domains?error=denied");
    if (err instanceof SurfaceError) return go(`/portal/domains?error=${err.code}`);
    return go("/portal/domains?error=generic");
  }
  return go("/portal/domains?ok=1");
}
