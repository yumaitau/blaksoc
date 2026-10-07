"use client";
import { passkeyClient } from "@better-auth/passkey/client";
import { ssoClient } from "@better-auth/sso/client";
import { twoFactorClient } from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({
  plugins: [
    ssoClient(),
    passkeyClient(),
    // Full navigation: the 2FA cookie set by the sign-in response must accompany the next request.
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination
    twoFactorClient({ onTwoFactorRedirect: () => { window.location.href = "/login/2fa"; } }),
  ],
});
