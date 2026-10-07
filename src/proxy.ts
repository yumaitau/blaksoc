import { getSessionCookie } from "better-auth/cookies";
import { NextResponse, type NextRequest } from "next/server";
import { REQUEST_ID_HEADER, requestIdFrom } from "@/lib/obs/request-id";

/**
 * Optimistic gate only: bounces requests without a session cookie to /login. Real
 * authorisation happens server-side in every page, action and route handler.
 * Machine endpoints (syslog ingest, the /api/v1 service API) authenticate with bearer tokens and are not gated here.
 *
 * Also stamps a request id on the request (for pages, actions and route handlers) and the response,
 * so a user-reported failure can be found in the logs and followed into the worker.
 */
export function proxy(request: NextRequest) {
  const id = requestIdFrom(request.headers);
  if (!getSessionCookie(request)) {
    const url = new URL("/login", request.url);
    url.searchParams.set("next", request.nextUrl.pathname);
    const res = NextResponse.redirect(url);
    res.headers.set(REQUEST_ID_HEADER, id);
    return res;
  }
  const forwarded = new Headers(request.headers);
  forwarded.set(REQUEST_ID_HEADER, id);
  const res = NextResponse.next({ request: { headers: forwarded } });
  res.headers.set(REQUEST_ID_HEADER, id);
  return res;
}

export const config = {
  matcher: ["/((?!api/auth|api/health|api/ingest|api/v1/|login|access-pending|_next/static|_next/image|favicon.ico|icon.svg|icon-192.png|icon-512.png|manifest.webmanifest|sw.js).*)"],
};
