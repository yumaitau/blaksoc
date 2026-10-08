"use client";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Label, Select } from "@/components/ui/input";
import { createServiceIdentityAction, revokeServiceIdentityAction, rotateServiceSecretAction, setServiceIdentityEnabledAction } from "./actions";

const PLATFORM = "platform";

/** The secret exists only in this response; blakSOC keeps a hash. */
function SecretOnce({ clientId, secret }: { clientId: string; secret: string }) {
  return (
    <div role="status" className="space-y-2 rounded-lg border border-warn/40 bg-warn/10 p-3 text-sm">
      <p className="font-medium">Copy the client secret now. It is shown once and cannot be recovered; rotate to get a new one.</p>
      <dl className="grid gap-1 font-mono text-xs sm:grid-cols-[8rem_1fr]">
        <dt className="text-muted">client_id</dt>
        <dd className="break-all select-all">{clientId}</dd>
        <dt className="text-muted">client_secret</dt>
        <dd className="break-all select-all">{secret}</dd>
      </dl>
      <p className="text-xs text-muted">
        Exchange them at <code>POST /api/v1/oauth/token</code> (grant_type=client_credentials) for a 15-minute bearer token. The API is described at <code>/api/v1/openapi.json</code>.
      </p>
    </div>
  );
}

export function CreateServiceIdentityForm({ targets }: { targets: { id: string | null; name: string; scopes: string[] }[] }) {
  const { pending, error, run } = useAction();
  const [name, setName] = useState("");
  const [target, setTarget] = useState(targets[0]?.id ?? PLATFORM);
  const [picked, setPicked] = useState<string[]>([]);
  const [issued, setIssued] = useState<{ id: string; clientSecret: string } | null>(null);
  const allowed = targets.find((t) => (t.id ?? PLATFORM) === target)?.scopes ?? [];

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        setIssued(null);
        run(() => createServiceIdentityAction({ name, tenantId: target === PLATFORM ? null : target, scopes: picked }), (data) => {
          if (data) setIssued(data);
          setName("");
          setPicked([]);
        }, { success: "Service identity created. Copy the secret below now." });
      }}
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <Label htmlFor="si-name">Name</Label>
          <Input id="si-name" value={name} required maxLength={80} placeholder="e.g. Ticketing sync" onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="si-target">Bound to</Label>
          <Select
            id="si-target"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
              setPicked([]);
            }}
          >
            {targets.map((t) => <option key={t.id ?? PLATFORM} value={t.id ?? PLATFORM}>{t.name}</option>)}
          </Select>
        </div>
      </div>
      <fieldset>
        <legend className="mb-1 text-xs font-medium text-muted">Scopes ({picked.length} selected). Only permissions you hold on this target are offered.</legend>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-3 lg:grid-cols-5">
          {allowed.map((p) => (
            <label key={p} className="flex items-center gap-1.5 font-mono text-[11.5px]">
              <Checkbox checked={picked.includes(p)} onCheckedChange={(v) => setPicked((x) => (v === true ? [...x, p] : x.filter((y) => y !== p)))} />
              {p}
            </label>
          ))}
        </div>
      </fieldset>
      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={pending || !name.trim() || !picked.length}>{pending ? "Creating…" : "Create service identity"}</Button>
        <ActionError error={error} />
      </div>
      {issued ? <SecretOnce clientId={issued.id} secret={issued.clientSecret} /> : null}
    </form>
  );
}

export function ServiceIdentityControls({ id, name, enabled, revoked }: { id: string; name: string; enabled: boolean; revoked: boolean }) {
  const { pending, error, run } = useAction();
  const [secret, setSecret] = useState<string | null>(null);
  if (revoked) return <span className="block text-right text-xs text-faint">revoked</span>;
  return (
    <div className="space-y-2 text-right">
      <div className="flex justify-end gap-1">
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={pending}
          onClick={() => confirm(`Rotate the secret for ${name}? The current secret and its tokens stop working immediately.`) && run(() => rotateServiceSecretAction(id), (data) => data && setSecret(data.clientSecret), { success: `Secret rotated for ${name}. Copy the new one now.` })}
        >
          Rotate
        </Button>
        <Button
          type="button"
          size="sm"
          variant={enabled ? "ghost" : "secondary"}
          disabled={pending}
          onClick={() => (!enabled || confirm(`Disable ${name}? Its tokens stop working immediately.`)) && run(() => setServiceIdentityEnabledAction(id, !enabled), undefined, { success: `${name} ${enabled ? "disabled" : "enabled"}` })}
        >
          {enabled ? "Disable" : "Enable"}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          className="text-danger"
          disabled={pending}
          onClick={() => confirm(`Revoke ${name} permanently? This cannot be undone.`) && run(() => revokeServiceIdentityAction(id), undefined, { success: `${name} revoked` })}
        >
          Revoke
        </Button>
      </div>
      <ActionError error={error} />
      {secret ? <div className="text-left"><SecretOnce clientId={id} secret={secret} /></div> : null}
    </div>
  );
}
