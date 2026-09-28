"use client";
import { useRouter } from "next/navigation";
import { useId, useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Input, Label, Select } from "@/components/ui/input";
import { linkTenantAction } from "../actions";

/** Link (or re-link) a customer to a shared integration. Re-linking replaces the agent groups. */
export function LinkTenantForm({ id, tenants, links }: { id: string; tenants: { id: string; name: string }[]; links: { tenantId: string; agentGroups: string[] }[] }) {
  const router = useRouter();
  const uid = useId();
  const groupsFor = (t: string) => links.find((l) => l.tenantId === t)?.agentGroups.join(", ") ?? "";
  const [tenantId, setTenantId] = useState(tenants[0]?.id ?? "");
  const [groups, setGroups] = useState(groupsFor(tenants[0]?.id ?? ""));
  const [done, setDone] = useState(false);
  const { pending, error, run } = useAction();
  if (!tenants.length) return <p className="text-sm text-muted">No customers available to link.</p>;
  return (
    <form
      className="grid items-end gap-3 md:grid-cols-[14rem_1fr_auto]"
      onSubmit={(e) => {
        e.preventDefault();
        setDone(false);
        run(() => linkTenantAction(id, tenantId, groups.split(",")), () => { setDone(true); router.refresh(); });
      }}
    >
      <div>
        <Label htmlFor={`${uid}-t`}>Customer</Label>
        <Select id={`${uid}-t`} value={tenantId} onChange={(e) => { setTenantId(e.target.value); setGroups(groupsFor(e.target.value)); setDone(false); }}>
          {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}{links.some((l) => l.tenantId === t.id) ? " (linked)" : ""}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor={`${uid}-g`}>Wazuh agent groups (comma-separated)</Label>
        <Input id={`${uid}-g`} value={groups} placeholder="acme-servers, acme-workstations" className="font-mono text-xs" onChange={(e) => { setGroups(e.target.value); setDone(false); }} />
      </div>
      <Button type="submit" variant="secondary" disabled={pending || !tenantId}>{pending ? "Saving…" : "Save link"}</Button>
      <div className="md:col-span-3">
        {done ? <span role="status" className="text-sm text-ok">Link saved.</span> : null}
        <ActionError error={error} />
      </div>
    </form>
  );
}
