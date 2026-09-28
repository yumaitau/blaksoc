"use client";
import { useRouter } from "next/navigation";
import { useId, useState } from "react";
import { ToggleSwitch } from "@/components/soc/toggle-switch";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { createIntegrationAction, updateIntegrationAction } from "./actions";

type Common = { provider: string; name: string; configJson: string; secretFields: { key: string; optional: boolean }[] };
type Props =
  | (Common & { mode: "create"; owners: { id: string | null; name: string }[] })
  | (Common & { mode: "edit"; id: string; hasSecret: boolean; enabled: boolean });

/** Secrets are write-only: inputs start empty and are cleared after every save. */
export function IntegrationForm(props: Props) {
  const router = useRouter();
  const uid = useId();
  const { pending, error, setError, run } = useAction();
  const [name, setName] = useState(props.name);
  const [owner, setOwner] = useState(props.mode === "create" ? (props.owners[0]?.id ?? "") : "");
  const [config, setConfig] = useState(props.configJson);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [enabled, setEnabled] = useState(props.mode === "edit" ? props.enabled : true);
  const [saved, setSaved] = useState(false);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaved(false);
    let parsed: unknown;
    try {
      parsed = JSON.parse(config || "{}");
    } catch {
      return setError("Configuration must be valid JSON.");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return setError("Configuration must be a JSON object.");
    if (props.mode === "create") {
      run(() => createIntegrationAction({ tenantId: owner || null, provider: props.provider, name, config: parsed, secrets }), (id) => router.push(id ? `/integrations/${id}` : "/integrations"));
    } else {
      run(() => updateIntegrationAction(props.id, { name, config: parsed, secrets, enabled }), () => {
        setSecrets({});
        setSaved(true);
        router.refresh();
      });
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4" autoComplete="off">
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <Label htmlFor={`${uid}-name`}>Name</Label>
          <Input id={`${uid}-name`} value={name} required maxLength={120} onChange={(e) => { setSaved(false); setName(e.target.value); }} />
        </div>
        {props.mode === "create" ? (
          <div>
            <Label htmlFor={`${uid}-owner`}>Owner</Label>
            <Select id={`${uid}-owner`} value={owner} onChange={(e) => setOwner(e.target.value)}>
              {props.owners.map((o) => <option key={o.id ?? "platform"} value={o.id ?? ""}>{o.name}</option>)}
            </Select>
            <p className="mt-1 text-[11px] text-faint">Platform integrations are shared and linked to customers separately.</p>
          </div>
        ) : (
          <div>
            <span className="mb-1 block text-xs font-medium text-muted">Status</span>
            <span className="inline-flex h-9 items-center gap-2 text-sm">
              <ToggleSwitch checked={enabled} onChange={(v) => { setSaved(false); setEnabled(v); }} label="Integration enabled" />
              {enabled ? "Enabled" : "Disabled"}
            </span>
          </div>
        )}
      </div>

      <div>
        <Label htmlFor={`${uid}-config`}>Configuration (JSON, non-secret)</Label>
        <Textarea id={`${uid}-config`} value={config} rows={Math.min(16, Math.max(5, config.split("\n").length + 1))} spellCheck={false} className="font-mono text-xs" onChange={(e) => { setSaved(false); setConfig(e.target.value); }} />
        <p className="mt-1 text-[11px] text-faint">Do not put passwords, tokens or keys here. Use the secret fields below.</p>
      </div>

      {props.secretFields.length ? (
        <fieldset className="space-y-2 rounded-md border border-border p-3">
          <legend className="px-1 text-xs font-medium text-muted">
            Secrets (write-only){props.mode === "edit" ? (props.hasSecret ? " · stored. Leave blank to keep the current value." : " · none stored yet") : ""}
          </legend>
          <div className="grid gap-3 md:grid-cols-2">
            {props.secretFields.map((f) => (
              <div key={f.key}>
                <Label htmlFor={`${uid}-s-${f.key}`}>{f.key}{f.optional ? " (optional)" : ""}</Label>
                <Input
                  id={`${uid}-s-${f.key}`}
                  type="password"
                  autoComplete="new-password"
                  value={secrets[f.key] ?? ""}
                  required={props.mode === "create" && !f.optional}
                  placeholder={props.mode === "edit" && props.hasSecret ? "•••••••• (unchanged)" : ""}
                  onChange={(e) => { setSaved(false); setSecrets((s) => ({ ...s, [f.key]: e.target.value })); }}
                />
              </div>
            ))}
          </div>
        </fieldset>
      ) : null}

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={pending}>{pending ? "Saving…" : props.mode === "create" ? "Add integration" : "Save changes"}</Button>
        {saved ? <span role="status" className="text-sm text-ok">Saved.</span> : null}
        <ActionError error={error} />
      </div>
    </form>
  );
}
