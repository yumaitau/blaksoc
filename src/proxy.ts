import { getSessionCookie } from "better-auth/cookies";
import { NextResponse, type NextRequest } from "next/server";
import { REQUEST_ID_HEADER, requestIdFrom } from "@/lib/obs/request-id";

/**
 * Paths reachable without a session cookie. Machine endpoints (syslog ingest, the /api/v1 service
 * API) authenticate with bearer tokens; auth, health, login and access-pending must stay reachable signed out.
 */
const PUBLIC_PATH = /^\/(?:api\/auth|api\/health|api\/ingest|api\/v1|login|access-pending)(?:\/|$)/;

export function isPublicPath(pathname: string) {
  return PUBLIC_PATH.test(pathname);
}

/**
 * Per-request Content-Security-Policy. Next.js reads the nonce from the request's CSP header
 * and stamps it on its own scripts; pages read it from `x-nonce` for their inline scripts.
 * 'strict-dynamic' lets nonce-trusted scripts load the rest of the bundle. Styles allow
 * 'unsafe-inline' because React style attributes and Radix (scroll lock) inject styles at runtime.
 */
export function contentSecurityPolicy(nonce: string, dev = process.env.NODE_ENV === "development") {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

/**
 * Sets the CSP on every matched response, and bounces requests without a session cookie to
 * /login. The redirect is an optimistic gate only: real authorisation happens server-side in
 * every page, action and route handler.
 *
 * Also stamps a request id on the request (for pages, actions and route handlers) and the response,
 * so a user-reported failure can be found in the logs and followed into the worker.
 */
export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const id = requestIdFrom(request.headers);
  if (!isPublicPath(pathname) && !getSessionCookie(request)) {
    const url = new URL("/login", request.url);
    url.searchParams.set("next", pathname);
    const res = NextResponse.redirect(url);
    res.headers.set(REQUEST_ID_HEADER, id);
    return res;
  }

  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = contentSecurityPolicy(nonce);
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  requestHeaders.set(REQUEST_ID_HEADER, id);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set(REQUEST_ID_HEADER, id);
  return response;
}

export const config = {
  // Everything except build assets, public/ files and better-auth's protocol endpoints. /api/auth is
  // public, and its SAML POST-binding pages (auto-submitting forms to the IdP) cannot carry our nonce.
  matcher: ["/((?!api/auth/|_next/static|_next/image|favicon.ico|icon.svg|icon-192.png|icon-512.png|manifest.webmanifest|sw.js|\\.well-known/).*)"],
};
