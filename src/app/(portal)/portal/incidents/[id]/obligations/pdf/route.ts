import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { ObligationError, obligationPdf } from "@/lib/services/obligations";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

export async function GET(req: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const access = await currentAccess();
  if (!access) return go("/login");
  try {
    const bytes = await obligationPdf(access, id);
    return new NextResponse(Buffer.from(bytes), {
      headers: {
        "content-type": "application/pdf",
        "content-disposition": "attachment; filename=\"breach-evidence.pdf\"",
      },
    });
  } catch (err) {
    if (err instanceof ObligationError || err instanceof AccessDenied) return go(`/portal/incidents/${id}?error=generic`);
    return go(`/portal/incidents/${id}?error=generic`);
  }
}
