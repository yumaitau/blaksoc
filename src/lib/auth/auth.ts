import { passkey } from "@better-auth/passkey";
import { sso } from "@better-auth/sso";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { nextCookies } from "better-auth/next-js";
import { genericOAuth, twoFactor } from "better-auth/plugins";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "@/db/client";
import { withScope } from "@/db/scope";
import { audit } from "@/lib/audit";
import * as schema from "@/db/schema";
import { env } from "@/lib/env";
import { parseTrustedProxies } from "@/lib/net/client-ip";
import { logger } from "@/lib/obs/log";
import { redis } from "@/lib/redis";
import { sharedRateLimitStore } from "./rate-limit";
import { cognitoProvider, cognitoIdentityRejection, legacySignInBlocked } from "./cognito";
import { ssoIdentityRejection } from "./sso-policy";

const e = env();

const cognito = cognitoProvider(e);

const appHost = new URL(e.APP_URL).hostname;

/** Credential changes recorded in the audit log. */
const PASSKEY_AUDIT: Record<string, string> = {
  "/passkey/verify-registration": "auth.passkey.add",
  "/passkey/delete-passkey": "auth.passkey.delete",
};

export const auth = betterAuth({
  appName: "blakSOC",
  // Better Auth's own messages go through the redacting logger (its args can include tokens or profiles).
  logger: { log: (level, message, ...args) => logger[level](`auth: ${message}`, args.length ? { args } : undefined) },
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
    validateUserInfo: ({ user, source }) => {
      if (source.oauth?.providerId !== "cognito") return;
      const error = cognitoIdentityRejection(user, e.COGNITO_ALLOWED_EMAIL_DOMAINS, source.oauth.profile);
      if (error) return { error, errorDescription: "This identity cannot access blakSOC." };
    },
    additionalFields: {
      isBreakGlass: { type: "boolean", input: false, defaultValue: false },
      disabled: { type: "boolean", input: false, defaultValue: false },
    },
  },
  // Retained for local demo/test fixtures; the production hook blocks legacy credentials.
  emailAndPassword: { enabled: true, disableSignUp: true, minPasswordLength: 16 },
  // Keep existing session lifetimes and freshness requirements during the provider migration.
  session: { expiresIn: 60 * 60 * 12, updateAge: 60 * 60, freshAge: 60 * 15 },
  // Counted in Redis so the limit holds across web replicas (see rate-limit.ts).
  rateLimit: { enabled: true, window: 60, max: 30, customStorage: sharedRateLimitStore(redis, (err) => logger.warn("auth rate limit fell back to per-process counting", { err })) },
  advanced: {
    useSecureCookies: e.NODE_ENV === "production",
    // Without trusted proxies, a multi-hop X-Forwarded-For resolves to no IP and every such client shares one rate-limit bucket.
    ipAddress: { trustedProxies: parseTrustedProxies(e.TRUSTED_PROXY_CIDRS) },
  },
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      // Local demo/test fixtures retain legacy auth; production signs in only through Cognito.
      if (!(e.NODE_ENV !== "production" && e.DEMO_MODE === "true") && legacySignInBlocked(ctx.path, ctx.params?.id)) {
        throw new APIError("FORBIDDEN", { message: "Sign in through Amazon Cognito." });
      }
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
    genericOAuth({ config: cognito ? [cognito] : [] }),
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
