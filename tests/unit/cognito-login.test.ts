import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ handler: vi.fn(), session: vi.fn(), warn: vi.fn() }));
vi.mock("@/lib/auth/auth", () => ({ auth: { handler: mocks.handler } }));
vi.mock("@/lib/auth/session", () => ({ getSessionState: mocks.session }));
vi.mock("@/lib/env", () => ({ env: () => ({ APP_URL: "https://soc.example", COGNITO_CLIENT_ID: "client", COGNITO_DOMAIN: "team.auth.ap-southeast-2.amazoncognito.com", COGNITO_REGION: "ap-southeast-2", COGNITO_USER_POOL_ID: "ap-southeast-2_pool" }) }));
vi.mock("@/lib/obs/log", () => ({ logger: { warn: mocks.warn } }));
vi.mock("next/navigation", () => ({ redirect: (url: string) => { throw new Error(`redirect:${url}`); } }));

import { GET } from "@/app/api/auth/cognito/route";
import { POST } from "@/app/api/auth/logout/route";
import LoginPage from "@/app/login/page";

const start = (next = "/soc?tenant=wattle") => GET(new Request(`https://soc.example/api/auth/cognito?${new URLSearchParams({ next, providerId: "untrusted" })}`, {
  headers: { cookie: "existing=cookie", "x-forwarded-for": "192.0.2.1" },
}));
const page = (params: { next?: string; error?: string; signedOut?: string } = {}) => LoginPage({ searchParams: Promise.resolve(params) });

beforeEach(() => {
  vi.resetAllMocks();
  mocks.session.mockResolvedValue({ state: "anonymous" });
  mocks.handler.mockImplementation(async () => {
    const headers = new Headers();
    headers.append("set-cookie", "state=state-value; HttpOnly; Secure; SameSite=Lax");
    headers.append("set-cookie", "pkce=verifier; HttpOnly; Secure; SameSite=Lax");
    return Response.json({ url: "https://team.auth.ap-southeast-2.amazoncognito.com/authorize?state=state-value", redirect: true }, { headers });
  });
});

describe("automatic Cognito sign-in", () => {
  it("starts without rendering an app login form", async () => {
    await expect(page({ next: "/soc?tenant=wattle" })).rejects.toThrow("redirect:/api/auth/cognito?next=%2Fsoc%3Ftenant%3Dwattle");
  });

  it("sends signed-in users to their original destination", async () => {
    mocks.session.mockResolvedValue({ state: "ok", access: {} });
    await expect(page({ next: "/soc?tenant=wattle" })).rejects.toThrow("redirect:/soc?tenant=wattle");
  });

  it("does not bypass an existing break-glass MFA requirement", async () => {
    mocks.session.mockResolvedValue({ state: "mfa_enrolment_required", userId: "admin" });
    await expect(page()).rejects.toThrow("redirect:/account/mfa");
  });

  it("stops automatic retries after errors and explicit sign-out", async () => {
    expect(await page({ error: "cognito" })).toBeTruthy();
    expect(await page({ signedOut: "1" })).toBeTruthy();
  });

  it("uses the configured provider and preserves state cookies on the browser redirect", async () => {
    const response = await start();
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("https://team.auth.ap-southeast-2.amazoncognito.com/authorize?state=state-value");
    expect(response.headers.getSetCookie()).toHaveLength(2);
    expect(response.headers.getSetCookie()[0]).toContain("state=state-value");
    expect(response.headers.getSetCookie()[1]).toContain("pkce=verifier");
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    const request = mocks.handler.mock.calls[0]![0] as Request;
    expect(request.url).toBe("https://soc.example/api/auth/sign-in/social");
    expect(request.method).toBe("POST");
    expect(request.headers.get("cookie")).toBe("existing=cookie");
    expect(request.headers.get("x-forwarded-for")).toBe("192.0.2.1");
    expect(await request.json()).toEqual({
      provider: "cognito", disableRedirect: true, callbackURL: "/soc?tenant=wattle",
      errorCallbackURL: "https://soc.example/login?error=cognito&next=%2Fsoc%3Ftenant%3Dwattle",
    });
  });

  it("rejects external and authentication return destinations", async () => {
    for (const next of ["//evil.example", "/login", "/api/auth/cognito", "/%6cogin?next=/login"]) {
      await start(next);
      const request = mocks.handler.mock.calls.at(-1)![0] as Request;
      expect((await request.json()).callbackURL).toBe("/");
    }
  });

  it.each(["none", "same-origin"])("supports %s browser navigation without Origin or Referer", async (site) => {
    await GET(new Request("https://soc.example/api/auth/cognito", { headers: {
      cookie: "existing=cookie", "sec-fetch-site": site, "sec-fetch-mode": "navigate", "sec-fetch-dest": "document",
    } }));
    const request = mocks.handler.mock.calls[0]![0] as Request;
    expect(request.headers.get("origin")).toBe("https://soc.example");
  });

  it("preserves cross-site request evidence for Better Auth's checks", async () => {
    for (const origin of [undefined, "https://evil.example"]) {
      await GET(new Request("https://soc.example/api/auth/cognito", { headers: {
        ...(origin ? { origin } : {}), "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document",
      } }));
      const request = mocks.handler.mock.calls.at(-1)![0] as Request;
      expect(request.headers.get("origin")).toBe(origin ?? null);
      expect(request.headers.get("sec-fetch-site")).toBe("cross-site");
    }
  });

  it.each([400, 403, 429, 500])("stops at a retry page when the provider returns %s", async (status) => {
    mocks.handler.mockResolvedValue(new Response("unavailable", { status }));
    const response = await start();
    const location = new URL(response.headers.get("location")!);
    expect(location.pathname).toBe("/login");
    expect(location.searchParams.get("error")).toBe("cognito");
    expect(location.searchParams.get("next")).toBe("/soc?tenant=wattle");
  });

  it("handles network failures and malformed provider responses without a redirect loop", async () => {
    for (const failure of [new Error("network unavailable"), {}, { url: "javascript:alert(1)" }, { url: "https://evil.example/authorize" }]) {
      if (failure instanceof Error) mocks.handler.mockRejectedValue(failure);
      else mocks.handler.mockResolvedValue(Response.json(failure));
      const response = await start();
      expect(response.headers.get("location")).toContain("/login?error=cognito");
      expect(response.headers.getSetCookie()).toEqual([]);
    }
  });

  it("clears local cookies and sends sign-out through Cognito", async () => {
    mocks.handler.mockResolvedValue(Response.json({ success: true }, { headers: { "set-cookie": "better-auth.session_token=; Max-Age=0; HttpOnly" } }));
    const response = await POST(new Request("https://soc.example/api/auth/logout", { method: "POST", headers: { origin: "https://soc.example", cookie: "better-auth.session_token=session" } }));
    const location = new URL(response.headers.get("location")!);
    expect(location.pathname).toBe("/logout");
    expect(location.searchParams.get("logout_uri")).toBe("https://soc.example/login?signedOut=1");
    expect(response.headers.getSetCookie()[0]).toContain("Max-Age=0");
    const request = mocks.handler.mock.calls[0]![0] as Request;
    expect(request.url).toBe("https://soc.example/api/auth/sign-out");
    expect(request.headers.get("origin")).toBe("https://soc.example");
  });

  it("does not claim sign-out succeeded when the auth handler refuses it", async () => {
    mocks.handler.mockResolvedValue(new Response("Forbidden", { status: 403 }));
    const response = await POST(new Request("https://soc.example/api/auth/logout", { method: "POST", headers: { origin: "https://evil.example" } }));
    expect(response.status).toBe(403);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.getSetCookie()).toEqual([]);
  });
});
