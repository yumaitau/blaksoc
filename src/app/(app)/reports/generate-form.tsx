"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Label, Select } from "@/components/ui/input";
import { generateReportAction } from "./actions";

type Option = { value: string; label: string };

export function GenerateReportForm({
  kinds,
  tenants,
  incidents,
  initial,
}: {
  kinds: Option[];
  tenants: Option[];
  incidents: { id: string; tenantId: string; label: string }[];
  initial: { kind?: string; tenant?: string; incident?: string };
}) {
  const router = useRouter();
  const { pending, error, run } = useAction();
  const [kind, setKind] = useState(kinds.some((k) => k.value === initial.kind) ? initial.kind! : "weekly");
  const [tenantId, setTenantId] = useState(tenants.some((t) => t.value === initial.tenant) ? initial.tenant! : (tenants[0]?.value ?? ""));
  const [incidentId, setIncidentId] = useState(initial.incident ?? "");
  const tenantIncidents = incidents.filter((i) => i.tenantId === tenantId);

  if (!tenants.length) return <p className="text-sm text-muted">You don&apos;t have permission to generate reports for any customer.</p>;

  return (
    <form
      className="grid gap-3 sm:grid-cols-[1fr_1fr_1.4fr_auto] sm:items-end"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => generateReportAction({ tenantId, kind, incidentId: kind === "incident" ? incidentId : undefined }), (d) => d && router.push(`/reports/${d.id}`));
      }}
    >
      <div>
        <Label htmlFor="report-kind">Report type</Label>
        <Select id="report-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          {kinds.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor="report-tenant">Customer</Label>
        <Select id="report-tenant" value={tenantId} onChange={(e) => { setTenantId(e.target.value); setIncidentId(""); }}>
          {tenants.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor="report-incident">Incident {kind === "incident" ? "" : "(incident reports only)"}</Label>
        <Select id="report-incident" value={incidentId} disabled={kind !== "incident"} onChange={(e) => setIncidentId(e.target.value)}>
          <option value="">{tenantIncidents.length ? "Choose an incident…" : "No incidents for this customer"}</option>
          {initial.incident && !tenantIncidents.some((i) => i.id === initial.incident) ? <option value={initial.incident}>{initial.incident}</option> : null}
          {tenantIncidents.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)}
        </Select>
      </div>
      <Button type="submit" disabled={pending || !tenantId}>{pending ? "Generating…" : "Generate"}</Button>
      <div className="sm:col-span-4"><ActionError error={error} /></div>
    </form>
  );
}
