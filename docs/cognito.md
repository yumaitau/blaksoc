# Cognito email/password sign-in and migration

blakSOC sends `/login` straight to Amazon Cognito managed login. Users enter their email and password
there and complete authenticator (TOTP) MFA. There is no second app login form, Google federation or
Google OAuth credential requirement. Postgres users, role assignments, tenant isolation and audit
actors remain in place. Retired Cloudflare OIDC callbacks are rejected by the new application.

## Provision before rollout

Deployed on 2026-10-13: stack `blaksoc-auth` (`CREATE_COMPLETE`), from change set
`native-password-20261013`. Pool: `ap-southeast-2_2jKCpYGkM`; public app client:
`7gaoc3sprutcum9vvej7kpp13d`; domain:
`blaksoc-959038055523.auth.ap-southeast-2.amazoncognito.com`.
Application release `d2191bed221c` deployed on 2026-10-13 as Helm revision 20, including the wallboard
and customisable dashboard. The two approved existing staff accounts were initially sent Cognito
temporary-password invitations. The owner then requested that invitations contain no passwords;
those passwords were invalidated and replaced with password-setup codes. Web/worker readiness,
public Postgres/Redis health, and a fresh HTTP redirect chain to
the Cognito password form passed; no Cloudflare prompt is in that chain. Initial password setup,
authenticator enrollment and the authenticated browser round trip still require the invited users.

Use AWS account `959038055523`, profile `homelab-admin`, region `ap-southeast-2`.

1. Deploy `deploy/aws/cognito.yaml` as a separate stack, `blaksoc-auth`, setting `DomainPrefix` to a
   unique name. The default `AppUrl` is `https://soc.yumait.au`. Review the change set before execution.
   The pool is retained on deletion/replacement and has deletion protection enabled.
2. Add `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID` and `COGNITO_DOMAIN` from the stack outputs to
   `blaksoc-eks-runtime`. The public app client uses code + PKCE and needs no client secret. Leave
   `COGNITO_CLIENT_SECRET` unset for this client.
3. Set `COGNITO_REGION=ap-southeast-2` and `COGNITO_ALLOWED_EMAIL_DOMAINS=yumait.com.au`. The domain is
   a hostname without `https://` or a trailing slash. Add customer email domains explicitly when they
   should sign in. Remove any retired `COGNITO_IDENTITY_PROVIDER` setting from local overrides.
4. Use password-setup codes for approved staff; **never send or resend temporary passwords**.
   Create accounts with `AdminCreateUser` and `MessageAction=SUPPRESS` so Cognito's default
   temporary-password invitation is not delivered. Do not use the console's send-invitation option.
   Verify the email against the existing verified identity as described below.
5. Cognito rejects `AdminResetUserPassword` while a user is in `FORCE_CHANGE_PASSWORD`. For a new
   pending account only, use `AdminSetUserPassword(Permanent=true)` with a cryptographically random
   bootstrap value generated and held only in SDK process memory, then immediately call
   `AdminResetUserPassword`. This invalidates the bootstrap value, moves the account to
   `RESET_REQUIRED`, and emails a code. Never print, persist, send, or place the bootstrap value in
   command-line arguments. Do not overwrite a confirmed user's chosen password during onboarding.
   If reset delivery fails after confirmation, retry the reset operation, not account creation.
6. Users open `https://soc.yumait.au/login`, select **Forgot your password?**, enter their email,
   and use the newest emailed code to choose their own password. Requesting a new code replaces the
   earlier setup code. They then sign in with email/password and enroll their authenticator.

Only the native `COGNITO` provider and password first factor are enabled. The template includes managed
login branding, required TOTP, a 16-character password policy, email password recovery, short ID/access
tokens, refresh-token rotation and revocation. Public self-registration is disabled. Cognito account
creation does not automatically grant blakSOC roles.

## Verify identities before linking

blakSOC requires `email_verified=true` in the Cognito ID token. An administrator-created account being
`CONFIRMED` does not, by itself, prove that its email is verified. For migrating known staff, verify the
approved address against the existing verified blakSOC identity before recording it as verified in
Cognito; deliver the password-setup code only to that address. Do not blanket-verify arbitrary
addresses or weaken the callback's verification check. New identities need verified email ownership
before admission as well. Password recovery also requires a verified email address.

## Cut over

- Verify existing staff rows have the correct verified email, are enabled, and have the intended roles.
  First Cognito sign-in links to these verified users, preserving IDs and permissions. Do not
  delete/recreate rows or rewrite roles to force migration. Use normal staff identities; retired
  local break-glass credentials are not the Cognito recovery mechanism.
- Deploy the reviewed application after the pool, initial accounts and runtime configuration exist.
  Check a fresh browser: app → Cognito email/password + TOTP → `/api/auth/callback/cognito` → original
  app page. Test initial password setup, password recovery, an existing staff account, an allowed
  account without roles, a disallowed domain, a disabled blakSOC user, and sign-out. Sign-out must
  clear both app and Cognito cookies without restarting login.
- Remove the **blakSOC** Cloudflare Access gate/SSO application after confirming Cognito works. Keep
  the previous image and provider configuration until rollback is no longer needed. Cloudflare DNS,
  Radar, ThreatSieve and Wazuh's Access/tunnel are independent of this change.
- Existing app sessions last up to 12 hours and are not deleted by this code change. Revoke them at
  cutover if all browsers must reauthenticate immediately. For immediate offboarding, disable the
  user in blakSOC as well as Cognito. Administrators handle MFA recovery after verifying identity.

## Development and checks

Use a separate development Cognito app client with exact callback
`http://localhost:3107/api/auth/callback/cognito` and logout
`http://localhost:3107/login?signedOut=1`. Keep production clients restricted to production URLs.

`pnpm test` covers redirects, PKCE/state cookies, unsafe return destinations, verified-email/domain
admission and logout. Signed callback tests exercise account linking and reject incorrect issuers,
audiences, expiry, signatures, nonce, token type, state and replay. The generic OAuth provider requires
ID-token verification on the code exchange. A real Cognito browser round trip remains a cutover check.

References: [Better Auth generic OAuth](https://better-auth.com/docs/plugins/generic-oauth),
[Cognito account creation](https://docs.aws.amazon.com/cognito/latest/developerguide/how-to-create-user-accounts.html),
[Admin password reset](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminResetUserPassword.html),
[Cognito password recovery](https://docs.aws.amazon.com/cognito/latest/developerguide/managing-users-passwords.html),
[Cognito logout](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html).
