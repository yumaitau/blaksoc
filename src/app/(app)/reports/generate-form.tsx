"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
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
  const [span, setSpan] = useState("month");
  const [preamble, setPreamble] = useState("");
  const [image, setImage] = useState<{ mime: string; data: string } | null>(null);
  const [imageError, setImageError] = useState("");
  const tenantIncidents = incidents.filter((i) => i.tenantId === tenantId);
  const board = kind === "board_summary";

  function onImage(file: File | undefined) {
    setImageError("");
    setImage(null);
    if (!file) return;
    if (file.size > 80_000) {
      setImageError("Use a PNG or JPEG image under 80 KB.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const url = String(reader.result ?? "");
      const match = url.match(/^data:(image\/(?:png|jpeg));base64,(.+)$/);
      if (!match?.[1] || !match[2]) {
        setImageError("Use a PNG or JPEG image under 80 KB.");
        return;
      }
      setImage({ mime: match[1], data: match[2] });
    };
    reader.readAsDataURL(file);
  }

  if (!tenants.length) return <p className="text-sm text-muted">You don&apos;t have permission to generate reports for any customer.</p>;

  return (
    <form
      className="grid gap-3 sm:grid-cols-[1fr_1fr_1.4fr_auto] sm:items-end"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => generateReportAction({
          tenantId,
          kind,
          incidentId: kind === "incident" ? incidentId : undefined,
          span: board ? span : undefined,
          preamble: board ? preamble : undefined,
          image: board ? image : undefined,
        }), (d) => d && router.push(`/reports/${d.id}`), { success: `${kinds.find((k) => k.value === kind)?.label ?? "Report"} generated` });
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
      <Button type="submit" disabled={pending || !tenantId || Boolean(imageError)}>{pending ? "Generating…" : "Generate"}</Button>
      {board ? (
        <div className="grid gap-3 sm:col-span-4 sm:grid-cols-2">
          <div>
            <Label htmlFor="report-span">Period</Label>
            <Select id="report-span" value={span} onChange={(e) => setSpan(e.target.value)}>
              <option value="month">About 30 days</option>
              <option value="quarter">About 90 days</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="report-image">Image (optional, PNG or JPEG)</Label>
            <Input id="report-image" type="file" accept="image/png,image/jpeg" onChange={(e) => onImage(e.target.files?.[0])} />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="report-preamble">Note from your group (optional)</Label>
            <Textarea id="report-preamble" value={preamble} maxLength={600} onChange={(e) => setPreamble(e.target.value)} />
          </div>
        </div>
      ) : null}
      <div className="sm:col-span-4"><ActionError error={error || imageError} /></div>
    </form>
  );
}
