import { redirect } from "next/navigation";
import { Wordmark } from "@/components/soc/brand";
import { getSessionState } from "@/lib/auth/session";
import { MfaEnrol } from "./mfa-enrol";

export const metadata = { title: "Enrol MFA" };

export default async function MfaPage() {
  const s = await getSessionState();
  if (s.state === "anonymous") redirect("/login");
  return (
    <main className="grid min-h-screen place-items-center px-4">
      <div className="w-full max-w-md space-y-4 rounded-lg border border-border bg-surface p-6">
        <Wordmark />
        <h1 className="text-lg font-semibold">Enrol multi-factor authentication</h1>
        <p className="text-sm text-muted">Break-glass accounts must use a TOTP authenticator before accessing blakSOC. Store the backup codes in the sealed break-glass envelope.</p>
        <MfaEnrol />
      </div>
    </main>
  );
}
