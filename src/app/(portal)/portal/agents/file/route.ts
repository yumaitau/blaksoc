import { NextResponse } from "next/server";
import { AccessDenied } from "@/lib/auth/access";
import { currentAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { AgentError, serveInstaller } from "@/lib/services/agents";

export async function GET(req: Request) {
  const access = await currentAccess();
  if (!access) return NextResponse.redirect(new URL("/login", env().APP_URL));
  const token = new URL(req.url).searchParams.get("token") ?? "";
  try {
    const file = await serveInstaller(access, token);
    return new NextResponse(file.body, {
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "content-disposition": `attachment; filename="${file.filename}"`,
      },
    });
  } catch (err) {
    const status = err instanceof AccessDenied ? 403 : 410;
    const message = err instanceof AgentError ? err.code : "denied";
    return new NextResponse(message, { status });
  }
}
