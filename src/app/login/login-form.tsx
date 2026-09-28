"use client";
import { KeyRound, LockKeyhole, Building2 } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { authClient } from "@/lib/auth/client";

export function LoginForm({ next, entraEnabled, demo, error }: { next: string; entraEnabled: boolean; demo: boolean; error?: string }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [breakGlass, setBreakGlass] = useState(demo);
  const [msg, setMsg] = useState<string | null>(error ? "Sign-in failed. Try again or contact the SOC." : null);
  const [busy, setBusy] = useState(false);

  async function sso(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    const res = await authClient.signIn.sso({ email, callbackURL: next, errorCallbackURL: "/login?error=sso" });
    if (res.error) setMsg(res.error.message ?? "No identity provider is registered for that email domain.");
    setBusy(false);
  }

  async function password_(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    const res = await authClient.signIn.email({ email, password, callbackURL: next });
    if (res.error) setMsg(res.error.message ?? "Sign-in failed.");
    else if (!(res.data as { twoFactorRedirect?: boolean } | null)?.twoFactorRedirect) window.location.href = next;
    setBusy(false);
  }

  return (
    <div className="rounded-lg border border-border bg-surface p-5">
      {entraEnabled ? (
        <>
          <Button className="w-full" size="lg" onClick={() => authClient.signIn.social({ provider: "microsoft", callbackURL: next, errorCallbackURL: "/login?error=entra" })}>
            <Building2 /> Sign in with Microsoft Entra ID
          </Button>
          <div className="my-4 flex items-center gap-3 text-[11px] uppercase tracking-wider text-faint">
            <span className="h-px flex-1 bg-border" />or<span className="h-px flex-1 bg-border" />
          </div>
        </>
      ) : null}

      {!breakGlass ? (
        <form onSubmit={sso} className="space-y-3">
          <div>
            <Label htmlFor="email">Work email</Label>
            <Input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@organisation.com.au" />
          </div>
          <Button type="submit" variant={entraEnabled ? "secondary" : "default"} className="w-full" disabled={busy}>
            <KeyRound /> Continue with organisation SSO
          </Button>
          <p className="text-xs text-muted">Uses your organisation&apos;s identity provider (OIDC or SAML), including its MFA policy.</p>
        </form>
      ) : (
        <form onSubmit={password_} className="space-y-3">
          <div>
            <Label htmlFor="bg-email">Email</Label>
            <Input id="bg-email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="bg-password">Password</Label>
            <Input id="bg-password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <Button type="submit" className="w-full" disabled={busy}>
            <LockKeyhole /> {demo ? "Sign in" : "Break-glass sign in"}
          </Button>
          {demo ? <p className="text-xs text-muted">Demo mode: personas such as <code className="font-mono">l2@demo.blaksoc.local</code> use password sign-in.</p> : <p className="text-xs text-warn">Emergency access only. Requires TOTP and is alerted to the SOC Manager.</p>}
        </form>
      )}

      {msg ? <p role="alert" className="mt-3 text-sm text-danger">{msg}</p> : null}

      <button type="button" onClick={() => setBreakGlass((b) => !b)} className="mt-4 w-full text-center text-xs text-faint hover:text-muted">
        {breakGlass ? "Use organisation SSO" : demo ? "Demo / break-glass sign in" : "Emergency break-glass access"}
      </button>
    </div>
  );
}
