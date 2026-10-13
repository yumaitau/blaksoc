import { NextResponse } from "next/server";
import { auth } from "@/lib/auth/auth";
import { cognitoLogoutUrl } from "@/lib/auth/cognito";
import { env } from "@/lib/env";

/** Clear the app session, then Cognito's managed-login cookie. */
export async function POST(request: Request) {
  const e = env();
  const headers = new Headers(request.headers);
  headers.set("content-type", "application/json");
  const result = await auth.handler(new Request(new URL("/api/auth/sign-out", e.APP_URL), {
    method: "POST", headers, body: "{}",
  }));
  if (!result.ok) return new Response("Sign-out failed. Please try again.", { status: result.status, headers: { "Cache-Control": "no-store" } });
  const response = NextResponse.redirect(cognitoLogoutUrl(e), 303);
  for (const cookie of result.headers.getSetCookie()) response.headers.append("set-cookie", cookie);
  response.headers.set("Cache-Control", "private, no-store");
  return response;
}
