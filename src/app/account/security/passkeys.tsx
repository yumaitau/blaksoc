"use client";
import { Fingerprint, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { authClient } from "@/lib/auth/client";

type Row = { id: string; name: string | null; createdAt: string; backedUp: boolean };

export function Passkeys({ rows }: { rows: Row[] }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    const res = await authClient.passkey.addPasskey({ name: name.trim() || undefined });
    if (res?.error) {
      // freshAge is 15 minutes: an older session must sign in again before adding a credential.
      setMsg(res.error.status === 403 ? "Sign out and sign in again, then add the passkey within 15 minutes." : (res.error.message ?? "Could not add the passkey."));
    } else {
      setName("");
      router.refresh();
    }
    setBusy(false);
  }

  async function remove(id: string) {
    setBusy(true);
    setMsg(null);
    const res = await authClient.passkey.deletePasskey({ id });
    if (res.error) setMsg(res.error.message ?? "Could not remove the passkey.");
    router.refresh();
    setBusy(false);
  }

  return (
    <div className="space-y-4">
      {rows.length ? (
        <ul className="divide-y divide-border rounded border border-border">
          {rows.map((p) => (
            <li key={p.id} className="flex items-center justify-between gap-2 px-3 py-2 text-sm">
              <div className="min-w-0">
                <div className="truncate font-medium">{p.name || "Unnamed passkey"}</div>
                <div className="text-[11px] text-faint">
                  Added {new Date(p.createdAt).toLocaleDateString("en-AU")} · {p.backedUp ? "synced" : "this device only"}
                </div>
              </div>
              <Button variant="ghost" size="icon" aria-label={`Remove ${p.name || "passkey"}`} disabled={busy} onClick={() => remove(p.id)}>
                <Trash2 />
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted">No passkeys yet.</p>
      )}
      <form onSubmit={add} className="space-y-3">
        <div>
          <Label htmlFor="pk-name">Name</Label>
          <Input id="pk-name" placeholder="Work laptop" maxLength={60} value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <Button type="submit" disabled={busy}>
          <Fingerprint /> Add a passkey
        </Button>
      </form>
      {msg ? <p role="alert" className="text-sm text-danger">{msg}</p> : null}
    </div>
  );
}
