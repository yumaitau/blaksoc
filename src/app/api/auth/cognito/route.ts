import { NextResponse } from "next/server";
import { auth } from "@/lib/auth/auth";
import { safeNextPath } from "@/lib/auth/next-path";
import { env } from "@/lib/env";
import { cognitoSettings } from "@/lib/auth/cognito";
import { logger } from "@/lib/obs/log";

/** Start the Cognito OIDC flow without an email form or provider picker. */
export async function GET(request: Request) {
  const e = env();
  const next = safeNextPath(new URL(request.url).searchParams.get("next") ?? undefined);
  const failure = new URL("/login", e.APP_URL);
  failure.searchParams.set("error", "cognito");
  failure.searchParams.set("next", next);
  let response: NextResponse;
  try {
    const config = cognitoSettings(e);
    if (!config) throw new Error("Cognito is not configured");
    const headers = new Headers(request.headers);
    headers.set("content-type", "application/json");
    // Top-level GETs from bookmarks and same-origin navigation need not carry Origin/Referer.
    // Supply an origin only when Fetch Metadata identifies such a navigation; never overwrite
    // explicit origins or bless cross-site requests when converting this GET into a POST.
    if (!headers.has("origin") && !headers.has("referer") &&
      ["same-origin", "none"].includes(headers.get("sec-fetch-site") ?? "") &&
      headers.get("sec-fetch-mode") === "navigate" && headers.get("sec-fetch-dest") === "document") {
      headers.set("origin", new URL(e.APP_URL).origin);
    }
    // Use the HTTP handler to retain Better Auth's state/PKCE, origin checks and rate limits.
    const result = await auth.handler(new Request(new URL("/api/auth/sign-in/social", e.APP_URL), {
      method: "POST",
      headers,
      body: JSON.stringify({
        provider: "cognito",
        disableRedirect: true,
        callbackURL: next,
        errorCallbackURL: failure.toString(),
      }),
    }));
    if (!result.ok) throw new Error(`Cognito sign-in returned ${result.status}`);
    const data = await result.json() as { url?: string };
    if (!data.url || new URL(data.url).protocol !== "https:") throw new Error("Cognito returned no HTTPS authorization URL");
    if (new URL(data.url).origin !== `https://${config.domain}`) throw new Error("Unexpected Cognito authorization origin");
    response = NextResponse.redirect(data.url, 303);
    // The browser needs the state cookie on the callback; never cache or discard it.
    for (const cookie of result.headers.getSetCookie()) response.headers.append("set-cookie", cookie);
  } catch (err) {
    logger.warn("Cognito sign-in could not start", { err });
    response = NextResponse.redirect(failure, 303);
  }
  response.headers.set("Cache-Control", "private, no-store");
  response.headers.set("Referrer-Policy", "no-referrer");
  return response;
}
