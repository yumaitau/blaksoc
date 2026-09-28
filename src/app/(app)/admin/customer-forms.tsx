"use client";
import { AlertTriangle } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Label, Select } from "@/components/ui/input";
import type { TenantSettings } from "@/db/schema";
import { createTenantAction, updateTenantSettingsAction } from "./actions";

export function CreateTenantForm({ sectors }: { sectors: readonly string[] }) {
  const router = useRouter();
  const { pending, error, run } = useAction();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [mode, setMode] = useState<"shared" | "dedicated">("shared");
  const [picked, setPicked] = useState<string[]>(["AUSTRALIA"]);
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => createTenantAction({ name, slug, sectors: picked, deploymentMode: mode }), (d) => {
          setName("");
          setSlug("");
          if (d) router.push(`/admin?tab=customers&tenant=${d.id}`);
        });
      }}
    >
      <div className="grid gap-3 sm:grid-cols-3">
        <div>
          <Label htmlFor="t-name">Customer name</Label>
          <Input id="t-name" value={name} required onChange={(e) => { setName(e.target.value); setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40)); }} />
        </div>
        <div>
          <Label htmlFor="t-slug">Slug</Label>
          <Input id="t-slug" value={slug} required pattern="[a-z0-9-]{2,40}" onChange={(e) => setSlug(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="t-mode">Deployment</Label>
          <Select id="t-mode" value={mode} onChange={(e) => setMode(e.target.value as "shared" | "dedicated")}>
            <option value="shared">Shared (multi-tenant)</option>
            <option value="dedicated">Dedicated</option>
          </Select>
        </div>
      </div>
      <fieldset>
        <legend className="mb-1 text-xs font-medium text-muted">Sectors (used to match threat intelligence)</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          {sectors.map((s) => (
            <label key={s} className="flex items-center gap-1.5 text-xs">
              <Checkbox checked={picked.includes(s)} onCheckedChange={(v) => setPicked((p) => (v === true ? [...p, s] : p.filter((x) => x !== s)))} />
              {s.replaceAll("_", " ").toLowerCase()}
            </label>
          ))}
        </div>
      </fieldset>
      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={pending}>{pending ? "Creating…" : "Create customer"}</Button>
        <ActionError error={error} />
      </div>
    </form>
  );
}

function Toggle({ id, label, hint, checked, onChange, disabled }: { id: string; label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <div className="flex items-start gap-2">
      <Checkbox id={id} checked={checked} disabled={disabled} onCheckedChange={(v) => onChange(v === true)} className="mt-0.5" />
      <label htmlFor={id} className="text-sm">
        {label}
        {hint ? <span className="block text-xs text-muted">{hint}</span> : null}
      </label>
    </div>
  );
}

export function TenantSettingsForm({ tenantId, initial, canAutoContainment }: { tenantId: string; initial: TenantSettings; canAutoContainment: boolean }) {
  const { pending, error, run } = useAction();
  const [s, setS] = useState(initial);
  const [providers, setProviders] = useState(initial.ai.allowedProviders.join(", "));
  const [saved, setSaved] = useState(false);
  const set = (fn: (x: TenantSettings) => TenantSettings) => {
    setSaved(false);
    setS(fn);
  };

  return (
    <form
      className="space-y-5"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => updateTenantSettingsAction(tenantId, { ...s, ai: { ...s.ai, allowedProviders: providers.split(",") } }, canAutoContainment), () => setSaved(true));
      }}
    >
      <fieldset className="space-y-3">
        <legend className="mb-2 text-xs font-semibold uppercase tracking-wider text-faint">Intelligence sharing</legend>
        <Toggle id="sh-sight" label="Create OpenCTI sightings for confirmed detections" checked={s.sharing.createSightings} onChange={(v) => set((x) => ({ ...x, sharing: { ...x.sharing, createSightings: v } }))} />
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="sh-attr">Attribution</Label>
            <Select id="sh-attr" value={s.sharing.attribution} onChange={(e) => set((x) => ({ ...x, sharing: { ...x.sharing, attribution: e.target.value as TenantSettings["sharing"]["attribution"] } }))}>
              <option value="anonymised">Anonymised (sector identity only)</option>
              <option value="named">Named customer</option>
              <option value="none">None</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="sh-tlp">Maximum TLP for shared data</Label>
            <Select id="sh-tlp" value={s.sharing.maxTlp} onChange={(e) => set((x) => ({ ...x, sharing: { ...x.sharing, maxTlp: e.target.value as TenantSettings["sharing"]["maxTlp"] } }))}>
              {["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"].map((t) => <option key={t} value={t}>{t}</option>)}
            </Select>
          </div>
        </div>
      </fieldset>

      <fieldset className="space-y-3">
        <legend className="mb-2 text-xs font-semibold uppercase tracking-wider text-faint">AI policy</legend>
        <Toggle id="ai-on" label="AI assistance enabled" checked={s.ai.enabled} onChange={(v) => set((x) => ({ ...x, ai: { ...x.ai, enabled: v } }))} />
        <div>
          <Label htmlFor="ai-prov">Allowed providers (comma-separated ids; empty = platform default)</Label>
          <Input id="ai-prov" value={providers} placeholder="e.g. ollama-local, bedrock-syd" onChange={(e) => { setSaved(false); setProviders(e.target.value); }} />
        </div>
        <Toggle id="ai-raw" label="Allow raw event payloads to reach the model" hint="Off: only normalised fields are sent." checked={s.ai.allowRawEvents} onChange={(v) => set((x) => ({ ...x, ai: { ...x.ai, allowRawEvents: v } }))} />
        <Toggle id="ai-pii" label="Redact personal information before model calls" checked={s.ai.redactPii} onChange={(v) => set((x) => ({ ...x, ai: { ...x.ai, redactPii: v } }))} />
      </fieldset>

      <fieldset>
        <legend className="mb-2 text-xs font-semibold uppercase tracking-wider text-faint">SLA (minutes to respond)</legend>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {(["critical", "high", "medium", "low"] as const).map((k) => (
            <div key={k}>
              <Label htmlFor={`sla-${k}`} className="capitalize">{k}</Label>
              <Input id={`sla-${k}`} type="number" min={1} max={43200} value={s.slaMinutes[k]} onChange={(e) => set((x) => ({ ...x, slaMinutes: { ...x.slaMinutes, [k]: Number(e.target.value) } }))} />
            </div>
          ))}
        </div>
      </fieldset>

      <fieldset className="rounded-md border border-danger/40 bg-danger/5 p-3">
        <legend className="px-1 text-xs font-semibold uppercase tracking-wider text-danger">Auto-containment</legend>
        <div className="mb-2 flex items-start gap-2 text-xs text-danger">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
          <span>
            When on, playbooks may isolate endpoints, disable identities and block indicators for this customer <strong>without a human approving each action</strong>.
            A false positive can take production systems or staff offline. Enable only with the customer&apos;s written agreement.
          </span>
        </div>
        <Toggle
          id="auto-contain"
          label={s.autoContainment ? "Auto-containment ON" : "Auto-containment off (every containment action needs approval)"}
          hint={canAutoContainment ? undefined : "Only platform administrators can change this."}
          checked={s.autoContainment}
          disabled={!canAutoContainment}
          onChange={(v) => set((x) => ({ ...x, autoContainment: v }))}
        />
      </fieldset>

      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={pending}>{pending ? "Saving…" : "Save settings"}</Button>
        {saved ? <span role="status" className="text-sm text-ok">Saved. The change is in the audit trail.</span> : null}
        <ActionError error={error} />
      </div>
    </form>
  );
}
