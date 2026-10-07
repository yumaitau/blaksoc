import { headers } from "next/headers";
import Link from "next/link";
import { Wordmark } from "@/components/soc/brand";
import { auth } from "@/lib/auth/auth";
import { requireAccess } from "@/lib/auth/session";
import { Passkeys } from "./passkeys";

export const metadata = { title: "Sign-in security" };

export default async function SecurityPage() {
  const ctx = await requireAccess();
  const rows = await auth.api.listPasskeys({ headers: await headers() });
  return (
    <main className="grid min-h-screen place-items-center px-4 font-sans">
      <div className="w-full max-w-md space-y-4 rounded-lg border border-border bg-surface p-6">
        <Wordmark />
        <h1 className="text-lg font-semibold">Passkeys</h1>
        <p className="text-sm text-muted">
          A passkey signs {ctx.principal.name} in with this device&apos;s screen lock or a security key, without a password or a trip to your identity provider. Removing your access in blakSOC also stops your passkeys working.
        </p>
        <Passkeys rows={rows.map((p) => ({ id: p.id, name: p.name ?? null, createdAt: new Date(p.createdAt).toISOString(), backedUp: p.backedUp }))} />
        <Link className="block text-xs text-faint hover:text-muted" href="/">Back to blakSOC</Link>
      </div>
    </main>
  );
}
