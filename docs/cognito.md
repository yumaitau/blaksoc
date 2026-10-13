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
Initial staff account setup and the application rollout are separate cutover steps below.

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
4. Create the approved staff accounts through Cognito administration and send invitations by email.
   Let Cognito generate temporary passwords; do not print, export, copy into scripts, or set permanent
   passwords for users. Users choose their own password and enroll their authenticator at first login.
   Temporary passwords expire after one day; resend an invitation if necessary.

Only the native `COGNITO` provider and password first factor are enabled. The template includes managed
login branding, required TOTP, a 16-character password policy, email password recovery, short ID/access
tokens, refresh-token rotation and revocation. Public self-registration is disabled. Cognito account
creation does not automatically grant blakSOC roles.

## Verify identities before linking

blakSOC requires `email_verified=true` in the Cognito ID token. An administrator-created account being
`CONFIRMED` does not, by itself, prove that its email is verified. For migrating known staff, verify the
approved address against the existing verified blakSOC identity before recording it as verified in
Cognito; deliver the generated temporary password only to that address. Do not blanket-verify arbitrary
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
[Cognito password recovery](https://docs.aws.amazon.com/cognito/latest/developerguide/managing-users-passwords.html),
[Cognito logout](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html).
