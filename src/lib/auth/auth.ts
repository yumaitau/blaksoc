import { sso } from "@better-auth/sso";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { nextCookies } from "better-auth/next-js";
import { twoFactor } from "better-auth/plugins";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "@/db/client";
import * as schema from "@/db/schema";
import { env } from "@/lib/env";
import { parseTrustedProxies } from "@/lib/net/client-ip";
import { redis } from "@/lib/redis";
import { sharedRateLimitStore } from "./rate-limit";

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

export const auth = betterAuth({
  appName: "blakSOC",
  baseURL: e.APP_URL,
  secret: e.BETTER_AUTH_SECRET,
  // Customer IdPs whose OIDC discovery documents blakSOC may fetch.
  trustedOrigins: [e.APP_URL, ...e.SSO_TRUSTED_ORIGINS.split(",").map((o) => o.trim()).filter(Boolean)],
  database: drizzleAdapter(db(), {
    provider: "pg",
    schema: {
      user: schema.user,
      session: schema.session,
      account: schema.account,
      verification: schema.verification,
      twoFactor: schema.twoFactor,
      ssoProvider: schema.ssoProvider,
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
  socialProviders: microsoft,
  session: { expiresIn: 60 * 60 * 12, updateAge: 60 * 60 },
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
    }),
    nextCookies(),
  ],
});

export type Auth = typeof auth;
