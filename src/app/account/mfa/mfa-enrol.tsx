"use client";
import QRCode from "qrcode";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { authClient } from "@/lib/auth/client";

export function MfaEnrol() {
  const [password, setPassword] = useState("");
  const [uri, setUri] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);

  async function start(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    const res = await authClient.twoFactor.enable({ password });
    if (res.error || !res.data || res.data.method !== "totp") return setErr(res.error?.message ?? "Could not start enrolment");
    setUri(res.data.totpURI);
    setCodes(res.data.backupCodes);
    setQr(await QRCode.toDataURL(res.data.totpURI, { margin: 1, width: 200 }));
  }

  async function verify(e: React.FormEvent) {
    e.preventDefault();
    const res = await authClient.twoFactor.verifyTotp({ code });
    if (res.error) setErr(res.error.message ?? "Invalid code");
    else window.location.href = "/";
  }

  if (!uri)
    return (
      <form onSubmit={start} className="space-y-3">
        <div>
          <Label htmlFor="pw">Confirm password</Label>
          <Input id="pw" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        {err ? <p className="text-sm text-danger">{err}</p> : null}
        <Button type="submit">Begin enrolment</Button>
      </form>
    );

  return (
    <form onSubmit={verify} className="space-y-4">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      {qr ? <img src={qr} alt="TOTP enrolment QR code" className="rounded bg-white p-2" width={200} height={200} /> : null}
      <details className="text-xs text-muted">
        <summary className="cursor-pointer">Can&apos;t scan? Show setup key</summary>
        <code className="mt-2 block break-all font-mono">{uri}</code>
      </details>
      <div className="rounded border border-border bg-bg p-3">
        <div className="mb-2 text-xs font-medium text-muted">Backup codes (shown once)</div>
        <div className="grid grid-cols-2 gap-1 font-mono text-sm">{codes.map((c) => <span key={c}>{c}</span>)}</div>
      </div>
      <div>
        <Label htmlFor="code">Enter the 6-digit code</Label>
        <Input id="code" inputMode="numeric" required value={code} onChange={(e) => setCode(e.target.value.trim())} />
      </div>
      {err ? <p className="text-sm text-danger">{err}</p> : null}
      <Button type="submit">Verify and continue</Button>
    </form>
  );
}
