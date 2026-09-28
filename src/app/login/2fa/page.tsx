"use client";
import { useState } from "react";
import { Wordmark } from "@/components/soc/brand";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { authClient } from "@/lib/auth/client";

export default function TwoFactorPage() {
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [backup, setBackup] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    const res = backup ? await authClient.twoFactor.verifyBackupCode({ code }) : await authClient.twoFactor.verifyTotp({ code });
    if (res.error) setErr(res.error.message ?? "Invalid code");
    else window.location.href = "/";
  }

  return (
    <main className="grid min-h-screen place-items-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-lg border border-border bg-surface p-5">
        <Wordmark />
        <div>
          <Label htmlFor="code">{backup ? "Backup code" : "Authenticator code"}</Label>
          <Input id="code" inputMode={backup ? "text" : "numeric"} autoComplete="one-time-code" autoFocus required value={code} onChange={(e) => setCode(e.target.value.trim())} />
        </div>
        {err ? <p role="alert" className="text-sm text-danger">{err}</p> : null}
        <Button type="submit" className="w-full">Verify</Button>
        <button type="button" className="w-full text-xs text-faint hover:text-muted" onClick={() => setBackup((b) => !b)}>
          {backup ? "Use authenticator app" : "Use a backup code"}
        </button>
      </form>
    </main>
  );
}
