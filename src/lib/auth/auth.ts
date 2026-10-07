import { passkey } from "@better-auth/passkey";
import { sso } from "@better-auth/sso";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { nextCookies } from "better-auth/next-js";
import { twoFactor } from "better-auth/plugins";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "@/db/client";
import { withScope } from "@/db/scope";
import { audit } from "@/lib/audit";
import * as schema from "@/db/schema";
import { env } from "@/lib/env";
import { parseTrustedProxies } from "@/lib/net/client-ip";
import { redis } from "@/lib/redis";
import { sharedRateLimitStore } from "./rate-limit";
import { ssoIdentityRejection } from "./sso-policy";

const e = env();

const microsoft =
  e.ENTRA_CLIENT_ID && e.ENTRA_CLIENT_SECRET
    ? {
        microsoft: {
          clientId: e.ENTRA_CLIENT_ID,
          clientSecret: e.ENTRA_CLIENT_SECRET,
          // Single-tenant: only the Yuma IT (or dedicated customer) Entra directory.
          tenantId: e.ENTRA_TENANT_ID ?? "organizations",
          prompt: "select_account" as const,
        },
      }
    : {};

const google =
  e.GOOGLE_CLIENT_ID && e.GOOGLE_CLIENT_SECRET && e.GOOGLE_HOSTED_DOMAIN
    ? {
        google: {
          clientId: e.GOOGLE_CLIENT_ID,
          clientSecret: e.GOOGLE_CLIENT_SECRET,
          // Staff Workspace only: sent as the `hd` hint and checked against the verified ID token.
          hd: e.GOOGLE_HOSTED_DOMAIN,
          prompt: "select_account" as const,
        },
      }
    : {};

const appHost = new URL(e.APP_URL).hostname;

/** Credential changes recorded in the audit log. */
const PASSKEY_AUDIT: Record<string, string> = {
  "/passkey/verify-registration": "auth.passkey.add",
  "/passkey/delete-passkey": "auth.passkey.delete",
};

export const auth = betterAuth({
  appName: "blakSOC",
  baseURL: e.APP_URL,
  secret: e.BETTER_AUTH_SECRET,
  // Customer IdPs whose OIDC discovery documents blakSOC may fetch.
  trustedOrigins: [e.APP_URL, ...e.SSO_TRUSTED_ORIGINS.split(",").map((o) => o.trim()).filter(Boolean)],
  database: drizzleAdapter(db(), {
    provider: "pg",
    // The SSO plugin's resolveUser hook runs inside an adapter transaction.
    transaction: true,
    schema: {
      user: schema.user,
      session: schema.session,
      account: schema.account,
      verification: schema.verification,
      twoFactor: schema.twoFactor,
      ssoProvider: schema.ssoProvider,
      passkey: schema.passkey,
    },
  }),
  user: {
    additionalFields: {
      isBreakGlass: { type: "boolean", input: false, defaultValue: false },
      disabled: { type: "boolean", input: false, defaultValue: false },
    },
  },
  // Password sign-in exists only for break-glass administrators; nobody self-registers.
  emailAndPassword: { enabled: true, disableSignUp: true, minPasswordLength: 16 },
  socialProviders: { ...microsoft, ...google },
  // freshAge: adding a passkey needs a sign-in from the last 15 minutes, so a stolen session cookie
  // cannot be turned into a credential that outlives it.
  session: { expiresIn: 60 * 60 * 12, updateAge: 60 * 60, freshAge: 60 * 15 },
  // Counted in Redis so the limit holds across web replicas (see rate-limit.ts).
  rateLimit: { enabled: true, window: 60, max: 30, customStorage: sharedRateLimitStore(redis, (err) => console.warn(`[auth] rate limit fell back to per-process counting: ${err instanceof Error ? err.message : err}`)) },
  advanced: {
    useSecureCookies: e.NODE_ENV === "production",
    // Without trusted proxies, a multi-hop X-Forwarded-For resolves to no IP and every such client shares one rate-limit bucket.
    ipAddress: { trustedProxies: parseTrustedProxies(e.TRUSTED_PROXY_CIDRS) },
  },
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      if (ctx.path !== "/sign-in/email") return;
      const email = String((ctx.body as { email?: string } | undefined)?.email ?? "").toLowerCase();
      const [u] = await db().select({ isBreakGlass: schema.user.isBreakGlass }).from(schema.user).where(eq(schema.user.email, email));
      // DEMO_MODE personas (…@demo.blaksoc.local) may use passwords so each role can be explored without an IdP.
      const demoPersona = e.DEMO_MODE === "true" && email.endsWith("@demo.blaksoc.local");
      if (!u?.isBreakGlass && !demoPersona) {
        throw new APIError("FORBIDDEN", { message: "Password sign-in is reserved for break-glass administrators. Use SSO." });
      }
    }),
    after: createAuthMiddleware(async (ctx) => {
      const action = PASSKEY_AUDIT[ctx.path];
      const userId = ctx.context.session?.user.id;
      if (!action || !userId || ctx.context.returned instanceof Error) return;
      await withScope({ tenantIds: [], platform: true }, (tx) =>
        audit(tx, { actorId: userId, actorKind: "user", tenantId: null, action, targetType: "user", targetId: userId, ip: ctx.context.session?.session.ipAddress ?? null }),
      );
    }),
  },
  databaseHooks: {
    session: {
      create: {
        before: async (session) => {
          const [u] = await db().select({ disabled: schema.user.disabled }).from(schema.user).where(eq(schema.user.id, session.userId));
          if (u?.disabled) return false;
          return { data: session };
        },
      },
    },
  },
  plugins: [
    twoFactor({ issuer: "blakSOC" }),
    passkey({ rpID: e.PASSKEY_RP_ID ?? appHost, rpName: "blakSOC", origin: e.APP_URL }),
    sso({
      // Providers are registered by platform admins only (see /admin); everyone else gets 0.
      providersLimit: async (u) => {
        const [grant] = await db()
          .select({ id: schema.roleAssignments.id })
          .from(schema.roleAssignments)
          .where(and(eq(schema.roleAssignments.userId, u.id), eq(schema.roleAssignments.roleKey, "platform_admin"), isNull(schema.roleAssignments.tenantId)));
        return grant ? 100 : 0;
      },
      schema: { ssoProvider: { additionalFields: { tenantId: { type: "string", required: false } } } },
      resolveUser: async (input, { database }) => {
        const provider = await database.findOne<{ domain: string }>({ model: "ssoProvider", where: [{ field: "providerId", value: input.providerId }] });
        const code = provider
          ? ssoIdentityRejection({
              email: input.providerUser.email,
              issuer: input.accountKey.issuer,
              domains: provider.domain,
              claims: input.protocol === "oidc" ? input.verifiedIdTokenClaims : undefined,
            })
          : "unknown_provider";
        return code ? { action: "reject", code, message: "This identity provider cannot sign in that account." } : { action: "continue" };
      },
    }),
    nextCookies(),
  ],
});

export type Auth = typeof auth;
