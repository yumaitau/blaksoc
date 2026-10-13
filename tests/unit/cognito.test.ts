import { describe, expect, it } from "vitest";
import { cognitoIdentityRejection, cognitoLogoutUrl, cognitoSettings, legacySignInBlocked } from "@/lib/auth/cognito";

const config = { COGNITO_REGION: "ap-southeast-2", COGNITO_USER_POOL_ID: "ap-southeast-2_example", COGNITO_CLIENT_ID: "client", COGNITO_DOMAIN: "blaksoc.auth.ap-southeast-2.amazoncognito.com" };

describe("Cognito authentication", () => {
  it("uses one configured pool for native email/password sign-in", () => {
    expect(cognitoSettings(config)).toMatchObject({ region: "ap-southeast-2", userPoolId: "ap-southeast-2_example", clientId: "client" });
    expect(cognitoSettings({ COGNITO_REGION: "ap-southeast-2" })).toBeNull();
    expect(() => cognitoSettings({ ...config, COGNITO_CLIENT_ID: "" })).toThrow("together");
    expect(() => cognitoSettings({ ...config, COGNITO_USER_POOL_ID: "us-east-1_wrong" })).toThrow("belong");
    for (const host of ["https://example.com", "example.com/path", "user@example.com", "example.com?x=1"]) {
      expect(() => cognitoSettings({ ...config, COGNITO_DOMAIN: host })).toThrow("hostname");
    }
  });

  it("admits verified email addresses in explicitly configured domains", () => {
    expect(cognitoIdentityRejection({ email: "justin@YUMAIT.COM.AU", emailVerified: true }, "yumait.com.au", { token_use: "id" })).toBeNull();
    expect(cognitoIdentityRejection({ email: "user@customer.au", emailVerified: true }, "yumait.com.au, customer.au", { token_use: "id" })).toBeNull();
    for (const email of ["user@gmail.com", "user@evil.yumait.com.au", "user@yumait.com.au.evil", "bad@x@yumait.com.au"]) {
      expect(cognitoIdentityRejection({ email, emailVerified: true }, "yumait.com.au", { token_use: "id" })).not.toBeNull();
    }
    for (const verified of [false, "true", undefined]) expect(cognitoIdentityRejection({ email: "user@yumait.com.au", emailVerified: verified }, "yumait.com.au", { token_use: "id" })).toBe("email_not_verified");
    expect(cognitoIdentityRejection({ email: "user@yumait.com.au", emailVerified: true }, "", { token_use: "id" })).toBe("email_domain_mismatch");
  });

  it("retires legacy sign-in and Cloudflare SSO callbacks", () => {
    for (const path of ["/sign-in/email", "/sign-in/sso", "/sso/callback/yumait-staff", "/passkey/verify-authentication", "/callback/google"]) expect(legacySignInBlocked(path)).toBe(true);
    for (const path of ["/sign-in/social", "/callback/cognito", "/get-session", "/sign-out"]) expect(legacySignInBlocked(path)).toBe(false);
    expect(legacySignInBlocked("/callback/:id", "cognito")).toBe(false);
    expect(legacySignInBlocked("/callback/:id", "google")).toBe(true);
    expect(legacySignInBlocked("/callback/:id")).toBe(true);
  });

  it("ends managed login without automatically starting sign-in again", () => {
    const url = new URL(cognitoLogoutUrl({ ...config, APP_URL: "https://soc.yumait.au" }));
    expect(url.origin).toBe(`https://${config.COGNITO_DOMAIN}`);
    expect(url.pathname).toBe("/logout");
    expect(url.searchParams.get("client_id")).toBe("client");
    expect(url.searchParams.get("logout_uri")).toBe("https://soc.yumait.au/login?signedOut=1");
  });
});
