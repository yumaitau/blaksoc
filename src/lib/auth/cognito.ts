import type { Env } from "@/lib/env";
import type { GenericOAuthConfig } from "better-auth/plugins/generic-oauth";

type Config = Pick<Env, "COGNITO_REGION" | "COGNITO_USER_POOL_ID" | "COGNITO_CLIENT_ID" | "COGNITO_CLIENT_SECRET" | "COGNITO_DOMAIN">;

export function cognitoSettings(e: Config) {
  const values = [e.COGNITO_USER_POOL_ID, e.COGNITO_CLIENT_ID, e.COGNITO_DOMAIN];
  if (values.every((v) => !v)) return null;
  if (values.some((v) => !v)) throw new Error("Set COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID and COGNITO_DOMAIN together");
  if (!/^[a-z]{2}-[a-z]+-\d$/.test(e.COGNITO_REGION) || !e.COGNITO_USER_POOL_ID!.startsWith(`${e.COGNITO_REGION}_`)) {
    throw new Error("COGNITO_USER_POOL_ID must belong to COGNITO_REGION");
  }
  if (e.COGNITO_DOMAIN!.length > 253 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(e.COGNITO_DOMAIN!)) throw new Error("COGNITO_DOMAIN must be a hostname without a scheme or path");
  return {
    clientId: e.COGNITO_CLIENT_ID!,
    clientSecret: e.COGNITO_CLIENT_SECRET || undefined,
    domain: e.COGNITO_DOMAIN!.toLowerCase(),
    region: e.COGNITO_REGION,
    userPoolId: e.COGNITO_USER_POOL_ID!,
  };
}

/** Require verified ID tokens and nonce binding on the authorization-code callback as well. */
export function cognitoProvider(e: Config): GenericOAuthConfig | null {
  const config = cognitoSettings(e);
  if (!config) return null;
  return {
    providerId: "cognito",
    name: "Amazon Cognito",
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    discoveryUrl: `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}/.well-known/openid-configuration`,
    authorizationUrl: `https://${config.domain}/oauth2/authorize`,
    tokenUrl: `https://${config.domain}/oauth2/token`,
    scopes: ["openid", "email", "profile"],
    pkce: true,
    requireIdTokenVerification: true,
    // Cognito uses logout_uri; our logout route handles its managed-login cookie explicitly.
    disableProviderLogout: true,
    mapProfileToUser: (profile) => ({ name: profile.name || profile.email || "" }),
  };
}

/** Cognito has verified the token; admission still requires a verified, permitted email. */
export function cognitoIdentityRejection(user: { email?: unknown; emailVerified?: unknown }, domains: string, profile?: Record<string, unknown>) {
  if (profile?.token_use !== "id") return "id_token_required";
  if (user.emailVerified !== true) return "email_not_verified";
  if (typeof user.email !== "string" || !/^[^\s@]+@[^\s@]+$/.test(user.email)) return "invalid_email";
  const allowed = domains.split(",").map((d) => d.trim().toLowerCase()).filter(Boolean);
  if (!allowed.includes(user.email.split("@")[1]!.toLowerCase())) return "email_domain_mismatch";
  return null;
}

/** Retire local credentials and legacy SSO callbacks without deleting historical accounts. */
export function legacySignInBlocked(path: string, callbackProvider?: string) {
  return path === "/sign-in/email" || path === "/sign-in/sso" || path.startsWith("/sso/") ||
    path.startsWith("/passkey/") || path.startsWith("/two-factor/") ||
    (path.startsWith("/callback/") && path !== "/callback/cognito" && !(path === "/callback/:id" && callbackProvider === "cognito"));
}

export function cognitoLogoutUrl(e: Config & { APP_URL: string }) {
  const config = cognitoSettings(e);
  const destination = new URL("/login?signedOut=1", e.APP_URL).toString();
  if (!config) return destination;
  const url = new URL(`https://${config.domain}/logout`);
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("logout_uri", destination);
  return url.toString();
}
