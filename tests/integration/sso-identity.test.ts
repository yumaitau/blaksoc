/**
 * End-to-end OIDC sign-ins through better-auth's SSO plugin against a local IdP, checking the
 * resolveUser guard in src/lib/auth/auth.ts: a customer IdP may only sign in its own domains,
 * and a Google issuer must also carry a matching `hd` claim.
 */
import { createSign, generateKeyPairSync, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const stamp = `sso${randomUUID().slice(0, 8)}`;
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: stamp, alg: "RS256", use: "sig" };

/** Claims the IdP puts in the next ID token. */
let nextClaims: Record<string, unknown> = {};
let issuer = "";
let server: Server;
let base = "";
let appUrl = "";
let auth: typeof import("@/lib/auth/auth").auth;
let adminDb: typeof import("@/db/client").adminDb;
let schema: typeof import("@/db/schema");

const b64 = (v: object | Buffer) => Buffer.from(v instanceof Buffer ? v : JSON.stringify(v)).toString("base64url");

function idToken(claims: Record<string, unknown>) {
  const head = b64({ alg: "RS256", kid: stamp, typ: "JWT" });
  const now = Math.floor(Date.now() / 1000);
  const body = b64({ iss: issuer, aud: `${stamp}-client`, iat: now, exp: now + 300, email_verified: true, ...claims });
  const sig = createSign("RSA-SHA256").update(`${head}.${body}`).sign(privateKey);
  return `${head}.${body}.${b64(sig)}`;
}

beforeAll(async () => {
  server = createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url?.startsWith("/jwks")) return res.end(JSON.stringify({ keys: [jwk] }));
    if (req.url?.startsWith("/token")) return res.end(JSON.stringify({ access_token: "at", token_type: "Bearer", expires_in: 300, id_token: idToken(nextClaims) }));
    res.statusCode = 404;
    res.end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  // Read once by env(); must be set before the auth module loads.
  process.env.SSO_TRUSTED_ORIGINS = base;
  ({ auth } = await import("@/lib/auth/auth"));
  ({ adminDb } = await import("@/db/client"));
  schema = await import("@/db/schema");
  appUrl = (await import("@/lib/env")).env().APP_URL;
});

afterAll(async () => {
  const { like } = await import("drizzle-orm");
  await adminDb().delete(schema.ssoProvider).where(like(schema.ssoProvider.providerId, `${stamp}%`));
  await adminDb().delete(schema.user).where(like(schema.user.email, `%@${stamp}.example`));
  await adminDb().delete(schema.user).where(like(schema.user.email, `%@other-${stamp}.example`));
  server.close();
});

async function register(providerId: string, iss: string, domain: string) {
  issuer = iss;
  await adminDb().insert(schema.ssoProvider).values({
    id: providerId,
    providerId,
    issuer: iss,
    domain,
    oidcConfig: JSON.stringify({
      issuer: iss,
      clientId: `${stamp}-client`,
      clientSecret: "secret",
      pkce: true,
      scopes: ["openid", "email", "profile"],
      skipDiscovery: true,
      authorizationEndpoint: `${base}/authorize`,
      tokenEndpoint: `${base}/token`,
      jwksEndpoint: `${base}/jwks`,
      tokenEndpointAuthentication: "client_secret_post",
    }),
  });
}

/** Starts an SSO sign-in, lets the IdP answer with `claims`, and returns the callback response. */
async function signIn(providerId: string, email: string, claims: Record<string, unknown>) {
  nextClaims = { sub: randomUUID(), email, ...claims };
  // Sign-in is rate limited per client address; give each attempt its own.
  const ip = `198.18.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  const start = await auth.handler(
    new Request(`${appUrl}/api/auth/sign-in/sso`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: appUrl, "x-forwarded-for": ip },
      body: JSON.stringify({ providerId, callbackURL: "/", errorCallbackURL: "/login?error=sso" }),
    }),
  );
  expect(start.status).toBe(200);
  const { url } = (await start.json()) as { url: string };
  const state = new URL(url).searchParams.get("state")!;
  const cookie = start.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  const done = await auth.handler(new Request(`${appUrl}/api/auth/sso/callback/${providerId}?code=c&state=${state}`, { headers: { cookie, "x-forwarded-for": ip } }));
  return { location: done.headers.get("location") ?? "", session: done.headers.getSetCookie().some((c) => c.includes("session_token=") && !c.includes("session_token=;")) };
}

describe("SSO identity guard", () => {
  it("signs in an address in the provider's domain", async () => {
    await register(`${stamp}-oidc`, `${base}/issuer`, `${stamp}.example`);
    const r = await signIn(`${stamp}-oidc`, `kim@${stamp}.example`, {});
    expect(r.location).not.toContain("error");
    expect(r.session).toBe(true);
  });

  it("refuses an address in another organisation's domain", async () => {
    issuer = `${base}/issuer`;
    const r = await signIn(`${stamp}-oidc`, `admin@other-${stamp}.example`, {});
    expect(r.location).toContain("error");
    expect(r.session).toBe(false);
  });

  it("requires Google's hosted-domain claim to match", async () => {
    await register(`${stamp}-google`, "https://accounts.google.com", `${stamp}.example`);
    const personal = await signIn(`${stamp}-google`, `lee@${stamp}.example`, {});
    expect(personal.location).toContain("error");
    expect(personal.session).toBe(false);
    const workspace = await signIn(`${stamp}-google`, `lee@${stamp}.example`, { hd: `${stamp}.example` });
    expect(workspace.location).not.toContain("error");
    expect(workspace.session).toBe(true);
  });
});
