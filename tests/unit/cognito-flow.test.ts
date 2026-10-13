import { createSign, generateKeyPairSync } from "node:crypto";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cognitoIdentityRejection, cognitoProvider, legacySignInBlocked } from "@/lib/auth/cognito";

const origin = "https://soc.example";
const domain = "blaksoc.auth.ap-southeast-2.amazoncognito.com";
const issuer = "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_test";
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const untrustedKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: "jwk" }), kid: "test-key", alg: "RS256", use: "sig" };
let claims: Record<string, unknown>;
let nonce: string;
let invalidSignature: boolean;
let database: Record<"user" | "account" | "session" | "verification", Record<string, unknown>[]>;
let auth: Pick<ReturnType<typeof betterAuth>, "handler">;

function idToken() {
  const now = Math.floor(Date.now() / 1000);
  const encode = (data: unknown) => Buffer.from(JSON.stringify(data)).toString("base64url");
  const payload = `${encode({ alg: "RS256", kid: "test-key" })}.${encode({ sub: "cognito-subject", iss: issuer, aud: "client", exp: now + 300, iat: now, token_use: "id", nonce, email: "user@yumait.com.au", email_verified: true, name: "Staff User", ...claims })}`;
  return `${payload}.${createSign("RSA-SHA256").update(payload).sign(invalidSignature ? untrustedKeys.privateKey : keys.privateKey).toString("base64url")}`;
}

beforeEach(() => {
  claims = {};
  invalidSignature = false;
  database = { user: [], account: [], session: [], verification: [] };
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === `${issuer}/.well-known/openid-configuration`) return Response.json({ issuer, authorization_endpoint: `https://${domain}/oauth2/authorize`, token_endpoint: `https://${domain}/oauth2/token`, jwks_uri: `${issuer}/.well-known/jwks.json`, id_token_signing_alg_values_supported: ["RS256"] });
    if (url === `https://${domain}/oauth2/token`) return Response.json({ access_token: "test-access", refresh_token: "test-refresh", token_type: "Bearer", expires_in: 300, id_token: idToken() });
    if (url === `${issuer}/.well-known/jwks.json`) return Response.json({ keys: [jwk] });
    throw new Error(`Unexpected test request: ${url}`);
  }));
  auth = betterAuth({
    baseURL: origin,
    secret: "cognito-flow-test-secret-at-least-32-characters",
    database: memoryAdapter(database),
    rateLimit: { enabled: false },
    logger: { disabled: true },
    plugins: [genericOAuth({ config: [cognitoProvider({ COGNITO_REGION: "ap-southeast-2", COGNITO_USER_POOL_ID: "ap-southeast-2_test", COGNITO_CLIENT_ID: "client", COGNITO_DOMAIN: domain })!] })],
    hooks: { before: createAuthMiddleware(async (ctx) => {
      if (legacySignInBlocked(ctx.path, ctx.params?.id)) throw new APIError("FORBIDDEN");
    }) },
    user: { validateUserInfo: ({ user, source }) => {
      if (source.oauth?.providerId !== "cognito") return;
      const error = cognitoIdentityRejection(user, "yumait.com.au", source.oauth.profile);
      if (error) return { error };
    } },
  });
});
afterEach(() => vi.unstubAllGlobals());

async function begin() {
  const response = await auth.handler(new Request(`${origin}/api/auth/sign-in/social`, {
    method: "POST", headers: { "content-type": "application/json", origin },
    body: JSON.stringify({ provider: "cognito", callbackURL: "/soc?tenant=customer", errorCallbackURL: "/login?error=cognito", disableRedirect: true }),
  }));
  expect(response.status).toBe(200);
  const url = new URL((await response.json()).url);
  nonce = url.searchParams.get("nonce")!;
  expect(nonce).toBeTruthy();
  const cookie = response.headers.getSetCookie().map((value) => value.split(";")[0]).join("; ");
  return { url, cookie };
}
async function complete(start: Awaited<ReturnType<typeof begin>>, state = start.url.searchParams.get("state")!) {
  return auth.handler(new Request(`${origin}/api/auth/callback/cognito?${new URLSearchParams({ code: "test-code", state })}`, { headers: { cookie: start.cookie } }));
}

describe("Cognito authorization-code round trip", () => {
  it("uses PKCE and native managed login, links an existing verified user and retains their local ID", async () => {
    database.user.push({ id: "existing-staff-id", name: "Staff User", email: "user@yumait.com.au", emailVerified: true, createdAt: new Date(), updatedAt: new Date() });
    const start = await begin();
    expect(start.url.origin).toBe(`https://${domain}`);
    expect(start.url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(start.url.searchParams.get("code_challenge")).toBeTruthy();
    expect(start.url.searchParams.has("identity_provider")).toBe(false);
    expect(start.url.searchParams.get("redirect_uri")).toBe(`${origin}/api/auth/callback/cognito`);
    const response = await complete(start);
    expect(response.headers.get("location")).toBe("/soc?tenant=customer");
    expect(database.user).toHaveLength(1);
    expect(database.session[0]?.userId).toBe("existing-staff-id");
    expect(database.account[0]?.providerId).toBe("cognito");
  });

  it.each([
    { email_verified: false }, { email: "user@other.example" }, { iss: "https://untrusted.example" },
    { aud: "another-client" }, { exp: 1 }, { nonce: "wrong-nonce" }, { token_use: "access" },
  ])("rejects untrusted token claims %j", async (override) => {
    claims = override;
    const response = await complete(await begin());
    expect(response.headers.get("location")).toContain("error=");
    expect(database.session).toHaveLength(0);
    expect(database.user).toHaveLength(0);
  });

  it("rejects a callback with the wrong state or without its browser cookie", async () => {
    const start = await begin();
    await complete(start, "wrong-state");
    expect(database.session).toHaveLength(0);
    await complete({ ...start, cookie: "" });
    expect(database.session).toHaveLength(0);
  });

  it("refuses to link into an unverified existing local account", async () => {
    database.user.push({ id: "unverified-id", name: "Unverified", email: "user@yumait.com.au", emailVerified: false, createdAt: new Date(), updatedAt: new Date() });
    await complete(await begin());
    expect(database.session).toHaveLength(0);
    expect(database.account).toHaveLength(0);
  });

  it("rejects forged signatures and replayed callbacks", async () => {
    invalidSignature = true;
    await complete(await begin());
    expect(database.session).toHaveLength(0);
    invalidSignature = false;
    const start = await begin();
    await complete(start);
    expect(database.session).toHaveLength(1);
    await complete(start);
    expect(database.session).toHaveLength(1);
  });
});
