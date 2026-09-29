import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { exportIrPlan, IrError } from "@/lib/services/ir";

function go(path: string) {
  return NextResponse.redirect(new URL(path, env().APP_URL), 303);
}

export async function GET(req: Request) {
  const access = await currentAccess();
  if (!access) return go("/login");
  const url = new URL(req.url);
  const format = url.searchParams.get("format") === "docx" ? "docx" : "pdf";
  const version = Number(url.searchParams.get("version") ?? "");
  try {
    const file = await exportIrPlan(access, url.searchParams.get("tenant") ?? "", version, format);
    const type = format === "docx" ? "application/vnd.openxmlformats-officedocument.wordprocessingml.document" : "application/pdf";
    return new NextResponse(Buffer.from(file.bytes), {
      headers: {
        "content-type": type,
        "content-disposition": `attachment; filename="ir-plan-v${version}.${format}"`,
      },
    });
  } catch (err) {
    if (err instanceof IrError || err instanceof AccessDenied) return go("/portal/ir");
    return go("/portal/ir");
  }
}
