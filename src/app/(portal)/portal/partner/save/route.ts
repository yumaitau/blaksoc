import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { escalateToSoc, partnerHome, setPartnerBrand } from "@/lib/services/partner";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

export async function POST(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  const partnerId = partnerHome(access);
  if (!partnerId) return go("/portal/partner");
  const form = await req.formData();
  try {
    if (form.get("intent") === "brand") {
      await setPartnerBrand(access, partnerId, String(form.get("brandName") ?? ""));
    } else if (form.get("intent") === "escalate") {
      await escalateToSoc(access, { tenantId: String(form.get("tenantId") ?? ""), note: String(form.get("note") ?? "") });
    }
  } catch (err) {
    if (!(err instanceof AccessDenied) && !(err instanceof Error)) throw err;
  }
  return go("/portal/partner");
}
