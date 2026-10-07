import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { config, contentSecurityPolicy, isPublicPath, proxy } from "@/proxy";

const matched = (path: string) => new RegExp(`^${config.matcher[0]}$`).test(path);
const request = (path: string, cookie?: string) =>
  new NextRequest(new URL(path, "http://localhost:3107"), { headers: cookie ? { cookie } : {} });
const SESSION = "better-auth.session_token=abc.def";

describe("session proxy matcher", () => {
  it("runs on pages, login and APIs so they all get the CSP", () => {
    for (const path of ["/soc", "/login", "/login/2fa", "/access-pending", "/portal", "/api/stream", "/api/ingest/syslog"]) {
      expect(matched(path), path).toBe(true);
    }
  });

  it("skips better-auth endpoints, build assets and public files", () => {
    for (const path of ["/api/auth/sign-in/email", "/api/auth/sso/saml2/sp/acs/x", "/_next/static/chunks/a.js", "/_next/image", "/sw.js", "/icon-192.png", "/manifest.webmanifest", "/.well-known/security.txt"]) {
      expect(matched(path), path).toBe(false);
    }
  });
});

describe("session gate", () => {
  it("does not send bearer-token machine endpoints or public pages to the login page", () => {
    for (const path of ["/api/ingest/syslog", "/api/health", "/api/health/live", "/api/auth/sign-in", "/login", "/login/2fa", "/access-pending"]) {
      expect(isPublicPath(path), path).toBe(true);
      expect(proxy(request(path)).headers.get("location"), path).toBeNull();
    }
  });

  it("still gates the app and session-authenticated APIs", () => {
    for (const path of ["/soc", "/api/stream", "/api/reports/abc/export", "/loginx", "/api/healthz"]) {
      expect(isPublicPath(path), path).toBe(false);
      const res = proxy(request(path));
      expect(res.status, path).toBe(307);
      const location = new URL(res.headers.get("location")!);
      expect(location.pathname).toBe("/login");
      expect(location.searchParams.get("next")).toBe(path);
    }
  });

  it("lets a request with a session cookie through", () => {
    expect(proxy(request("/soc", SESSION)).headers.get("location")).toBeNull();
  });
});

describe("content security policy", () => {
  it("sets a nonce-based CSP on the response and forwards the nonce to rendering", () => {
    const res = proxy(request("/login"));
    const csp = res.headers.get("content-security-policy")!;
    const nonce = /'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toContain(`script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`);
    // NextResponse.next({ request }) carries overridden request headers to the renderer.
    expect(res.headers.get("x-middleware-request-x-nonce")).toBe(nonce);
    expect(res.headers.get("x-middleware-request-content-security-policy")).toBe(csp);
  });

  it("uses a fresh nonce per request", () => {
    const a = proxy(request("/soc", SESSION)).headers.get("content-security-policy");
    const b = proxy(request("/soc", SESSION)).headers.get("content-security-policy");
    expect(a).not.toBe(b);
  });

  it("locks down framing, plugins, base and forms, and keeps SSE and the service worker same-origin", () => {
    const csp = contentSecurityPolicy("n0nce", false);
    for (const directive of [
      "default-src 'self'",
      "connect-src 'self'",
      "worker-src 'self'",
      "img-src 'self' data: blob:",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ]) {
      expect(csp).toContain(directive);
    }
    expect(csp).not.toContain("unsafe-eval");
    expect(contentSecurityPolicy("n0nce", true)).toContain("'unsafe-eval'");
  });
});
