import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { assessmentPdf, EssentialEightError } from "@/lib/services/essential-eight";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

export async function GET(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  const url = new URL(req.url);
  try {
    const bytes = await assessmentPdf(access, url.searchParams.get("tenant") ?? "", url.searchParams.get("id") ?? "");
    return new NextResponse(Buffer.from(bytes), {
      headers: {
        "content-type": "application/pdf",
        "content-disposition": "attachment; filename=\"essential-eight.pdf\"",
      },
    });
  } catch (err) {
    if (err instanceof EssentialEightError || err instanceof AccessDenied) return go("/portal/essential-eight?error=generic");
    return go("/portal/essential-eight?error=generic");
  }
}
