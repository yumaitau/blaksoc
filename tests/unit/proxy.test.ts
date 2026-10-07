import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { config, proxy } from "@/proxy";

const gated = (path: string) => new RegExp(`^${config.matcher[0]}$`).test(path);

describe("session proxy matcher", () => {
  it("does not send bearer-token machine endpoints to the login page", () => {
    expect(gated("/api/ingest/syslog")).toBe(false);
    expect(gated("/api/health")).toBe(false);
    expect(gated("/api/auth/sign-in")).toBe(false);
    expect(gated("/api/v1/alerts")).toBe(false);
    expect(gated("/api/v1/oauth/token")).toBe(false);
  });

  it("still gates the app and session-authenticated APIs", () => {
    expect(gated("/soc")).toBe(true);
    expect(gated("/api/stream")).toBe(true);
    expect(gated("/api/reports/abc/export")).toBe(true);
  });
});

describe("request id", () => {
  const signedIn = (headers: Record<string, string> = {}) => new NextRequest("https://soc.example/alerts", { headers: { cookie: "better-auth.session_token=abc", ...headers } });

  it("stamps a new id on the forwarded request and the response", () => {
    const res = proxy(signedIn());
    const id = res.headers.get("x-request-id");
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    // NextResponse.next({ request: { headers } }) marks overridden request headers for the route.
    expect(res.headers.get("x-middleware-request-x-request-id")).toBe(id);
  });

  it("keeps a well-formed upstream id and replaces one that could inject into logs", () => {
    expect(proxy(signedIn({ "x-request-id": "ingress-abc123def" })).headers.get("x-request-id")).toBe("ingress-abc123def");
    const forged = proxy(signedIn({ "x-request-id": 'x","level":"info' })).headers.get("x-request-id");
    expect(forged).not.toContain('"');
  });

  it("returns the id on the sign-in redirect too", () => {
    const res = proxy(new NextRequest("https://soc.example/alerts"));
    expect(res.status).toBe(307);
    expect(res.headers.get("x-request-id")).toBeTruthy();
  });
});
