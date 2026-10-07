import { describe, expect, it } from "vitest";
import { emailInDomains, GOOGLE_ISSUER, googleEndpoints, ssoIdentityRejection } from "@/lib/auth/sso-policy";

describe("emailInDomains", () => {
  it("matches the domain, its subdomains and any listed domain", () => {
    expect(emailInDomains("a@wattle.com.au", "wattle.com.au")).toBe(true);
    expect(emailInDomains("a@mail.wattle.com.au", "wattle.com.au")).toBe(true);
    expect(emailInDomains("a@WATTLE.org", "wattle.com.au, wattle.org")).toBe(true);
  });

  it("refuses look-alike suffixes and missing domains", () => {
    expect(emailInDomains("a@evilwattle.com.au", "wattle.com.au")).toBe(false);
    expect(emailInDomains("a@wattle.com.au.evil.io", "wattle.com.au")).toBe(false);
    expect(emailInDomains("no-at-sign", "wattle.com.au")).toBe(false);
    expect(emailInDomains("a@wattle.com.au", "")).toBe(false);
  });
});

describe("ssoIdentityRejection", () => {
  const entra = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0";

  it("lets a customer IdP sign in its own domain", () => {
    expect(ssoIdentityRejection({ email: "kim@wattle.com.au", issuer: entra, domains: "wattle.com.au" })).toBeNull();
  });

  it("refuses an IdP asserting another organisation's address", () => {
    expect(ssoIdentityRejection({ email: "admin@yumait.com.au", issuer: entra, domains: "wattle.com.au" })).toBe("email_domain_mismatch");
  });

  it("requires a Google hosted-domain claim for the provider's domain", () => {
    const base = { email: "kim@wattle.com.au", issuer: GOOGLE_ISSUER, domains: "wattle.com.au" };
    expect(ssoIdentityRejection({ ...base, claims: { hd: "wattle.com.au" } })).toBeNull();
    // A personal Google account has no hd claim, even when its address looks right.
    expect(ssoIdentityRejection({ ...base, claims: {} })).toBe("google_hosted_domain_mismatch");
    expect(ssoIdentityRejection({ ...base, claims: { hd: "other.com.au" } })).toBe("google_hosted_domain_mismatch");
    expect(ssoIdentityRejection({ ...base, issuer: "accounts.google.com", claims: { hd: "other.com.au" } })).toBe("google_hosted_domain_mismatch");
  });
});

describe("googleEndpoints", () => {
  it("skips discovery for Google and leaves other issuers alone", () => {
    expect(googleEndpoints(`${GOOGLE_ISSUER}/`)).toMatchObject({ skipDiscovery: true, tokenEndpoint: "https://oauth2.googleapis.com/token" });
    expect(googleEndpoints("https://idp.example.com")).toEqual({});
  });
});
