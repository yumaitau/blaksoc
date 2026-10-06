import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  APP_URL: z.string().url().default("http://localhost:3000"),
  /** App role connection — RLS enforced. */
  DATABASE_URL: z.string().default("postgres://blaksoc_app:blaksoc_app@localhost:5432/blaksoc"),
  /** System role connection — worker jobs and pre-scope web paths. Not the owner. */
  DATABASE_SYSTEM_URL: z.string().default("postgres://blaksoc_system:blaksoc_system@localhost:5432/blaksoc"),
  /** Owner connection — migrations and seed only. */
  DATABASE_ADMIN_URL: z.string().default("postgres://blaksoc:blaksoc@localhost:5432/blaksoc"),
  BLAKSOC_APP_DB_PASSWORD: z.string().default("blaksoc_app"),
  BLAKSOC_SYSTEM_DB_PASSWORD: z.string().default("blaksoc_system"),
  REDIS_URL: z.string().default("redis://localhost:6379"),
  BETTER_AUTH_SECRET: z.string().min(32).default("dev-only-secret-change-me-dev-only-secret"),
  /** 32-byte key, base64. Encrypts integration secrets at rest. */
  BLAKSOC_ENCRYPTION_KEY: z.string().default("ZGV2LW9ubHkta2V5LWNoYW5nZS1tZS0zMi1ieXRlcyE="),
  ENTRA_TENANT_ID: z.string().optional(),
  ENTRA_CLIENT_ID: z.string().optional(),
  ENTRA_CLIENT_SECRET: z.string().optional(),
  /** Australian Business Register web services GUID. Unset: setup checks the ATO example ABN only. */
  ABR_GUID: z.string().optional(),
  /** Multi-tenant Entra app that customers' admins consent to for Graph reads. Separate from the staff sign-in app. */
  M365_CONNECTOR_CLIENT_ID: z.string().optional(),
  M365_CONNECTOR_CLIENT_SECRET: z.string().optional(),
  /** Comma-separated OIDC issuer origins allowed for SSO discovery (Entra endpoints are preconfigured). */
  SSO_TRUSTED_ORIGINS: z.string().default(""),
  /** Break-glass accounts must also pass TOTP. Disable only for local dev. */
  BREAK_GLASS_REQUIRE_MFA: z.enum(["true", "false"]).default("true"),
  /**
   * CIDRs of the proxies in front of blakSOC (ingress controller, load balancer, VPC). With it set,
   * client addresses are read from the right of X-Forwarded-For past these proxies; without it only
   * a single-entry header is trusted. Used by sign-in rate limits and syslog source allowlists.
   */
  TRUSTED_PROXY_CIDRS: z.string().default(""),
  /** "AU" restricts AI inference to providers declaring Australian residency. */
  AI_DATA_RESIDENCY: z.enum(["AU", "ANY"]).default("AU"),
  DEMO_MODE: z.enum(["true", "false"]).default("false"),
});

export type Env = z.infer<typeof schema>;

let cached: Env | undefined;

export function env(): Env {
  if (!cached) {
    cached = schema.parse(process.env);
    // `next build` evaluates route modules to collect page data. Secrets exist only at runtime.
    if (cached.NODE_ENV === "production" && process.env.NEXT_PHASE !== "phase-production-build") {
      // Development defaults for these would connect production to the wrong database or key.
      for (const key of ["BETTER_AUTH_SECRET", "BLAKSOC_ENCRYPTION_KEY", "DATABASE_URL", "DATABASE_SYSTEM_URL", "REDIS_URL"] as const) {
        if (!process.env[key]) throw new Error(`${key} must be set in production`);
      }
    }
  }
  return cached;
}
