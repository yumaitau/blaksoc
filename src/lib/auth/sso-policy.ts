/** Google is the OIDC issuer for every Workspace customer; the tenant is told apart by the `hd` claim. */
export const GOOGLE_ISSUER = "https://accounts.google.com";

/** True when the email's domain is one of the provider's comma-separated domains or a subdomain of one. */
export function emailInDomains(email: string, domains: string): boolean {
  const host = email.split("@")[1]?.trim().toLowerCase();
  if (!host) return false;
  return domains
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean)
    .some((d) => host === d || host.endsWith(`.${d}`));
}

function isGoogleIssuer(issuer: string) {
  return issuer.replace(/\/$/, "") === GOOGLE_ISSUER || issuer === "accounts.google.com";
}

/**
 * Why a verified SSO identity may not sign in through a customer IdP, or null when it may.
 * A customer IdP only vouches for its own domains, so an assertion for another organisation's
 * address is refused. Google's issuer is shared by every Workspace and by personal accounts,
 * so a Google sign-in must also carry an `hd` claim for one of the provider's domains.
 */
export function ssoIdentityRejection(input: { email: string; issuer: string; domains: string; claims?: Record<string, unknown> }): string | null {
  if (!emailInDomains(input.email, input.domains)) return "email_domain_mismatch";
  if (isGoogleIssuer(input.issuer)) {
    const hd = input.claims?.hd;
    if (typeof hd !== "string" || !emailInDomains(`x@${hd}`, input.domains)) return "google_hosted_domain_mismatch";
  }
  return null;
}

/**
 * Google's endpoints are fixed, so discovery is skipped. No userinfo endpoint: the verified
 * ID token carries `email`, `email_verified` and `hd`.
 */
export function googleEndpoints(issuer: string) {
  if (!isGoogleIssuer(issuer)) return {};
  return {
    skipDiscovery: true,
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    jwksEndpoint: "https://www.googleapis.com/oauth2/v3/certs",
    tokenEndpointAuthentication: "client_secret_post" as const,
  };
}
