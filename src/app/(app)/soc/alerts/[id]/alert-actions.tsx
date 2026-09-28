"use client";
import { FilePlus2, ShieldAlert, UserCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { RESPONSE_ACTIONS, type ResponseActionKey } from "@/lib/soar/actions";
import { assignAlertsToMe, createIncidentFromSelection, requestAlertResponse, setAlertStatus } from "../actions";

type Props = {
  alertId: string;
  tenantId: string;
  status: string;
  statuses: readonly string[];
  assignedToMe: boolean;
  hasIncident: boolean;
  canTriage: boolean;
  canEscalate: boolean;
};

export function AlertActions({ alertId, tenantId, status, statuses, assignedToMe, hasIncident, canTriage, canEscalate }: Props) {
  const router = useRouter();
  const { pending, error, run } = useAction();

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        {canTriage ? (
          <>
            <label className="sr-only" htmlFor="alert-status">Alert status</label>
            <Select id="alert-status" className="h-8 w-44 text-xs" value={status} disabled={pending} onChange={(e) => run(() => setAlertStatus([alertId], e.target.value))}>
              {statuses.map((s) => <option key={s} value={s}>{s.replaceAll("_", " ")}</option>)}
            </Select>
            {!assignedToMe ? (
              <Button size="sm" variant="secondary" disabled={pending} onClick={() => run(() => assignAlertsToMe([alertId]))}>
                <UserCheck /> Assign to me
              </Button>
            ) : null}
          </>
        ) : null}
        {canEscalate && !hasIncident ? (
          <Button size="sm" variant="secondary" disabled={pending} onClick={() => run(() => createIncidentFromSelection([alertId], [tenantId]), (d) => d && router.push(`/soc/incidents/${d.id}`))}>
            <FilePlus2 /> Escalate to incident
          </Button>
        ) : null}
      </div>
      <ActionError error={error} />
    </div>
  );
}

export function RequestResponseDialog({ alertId, tenantId, assetId, assetName, identity, observables }: {
  alertId: string;
  tenantId: string;
  assetId: string | null;
  assetName: string | null;
  identity: string | null;
  observables: { type: string; value: string }[];
}) {
  const [open, setOpen] = useState(false);
  const [action, setAction] = useState<ResponseActionKey>("isolate_endpoint");
  const [reason, setReason] = useState("");
  const [ident, setIdent] = useState(identity ?? "");
  const [ip, setIp] = useState(observables.find((o) => o.type === "ipv4" || o.type === "ipv6")?.value ?? "");
  const [ioc, setIoc] = useState(observables[0]?.value ?? "");
  const [proc, setProc] = useState("");
  const [done, setDone] = useState<string | null>(null);
  const { pending, error, run } = useAction();
  const def = RESPONSE_ACTIONS[action];
  const needsAsset = def.target.startsWith("asset");

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const target =
      def.target === "asset" ? { assetId: assetId ?? undefined, process: action === "kill_process" ? proc : undefined }
      : def.target === "asset+ip" ? { assetId: assetId ?? undefined, ip }
      : def.target === "identity" ? { identity: ident }
      : { observable: ioc };
    run(() => requestAlertResponse({ alertId, tenantId, action, reason, target }), (d) => {
      setDone(d?.needsApproval ? "Requested. It is waiting for a SOC Manager's approval before anything runs." : "Requested and queued for execution.");
      setReason("");
    });
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) setDone(null); }}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline"><ShieldAlert /> Request response action</Button>
      </DialogTrigger>
      <DialogContent title="Request response action" description="Actions run against the customer's real systems through the owning integration.">
        {done ? (
          <div className="space-y-3">
            <p role="status" className="text-sm text-ok">{done}</p>
            <div className="flex justify-end"><Button variant="secondary" onClick={() => setOpen(false)}>Close</Button></div>
          </div>
        ) : (
          <form className="space-y-3" onSubmit={submit}>
            <div>
              <Label htmlFor="ra-action">Action</Label>
              <Select id="ra-action" value={action} onChange={(e) => setAction(e.target.value as ResponseActionKey)}>
                {(Object.entries(RESPONSE_ACTIONS) as [ResponseActionKey, (typeof RESPONSE_ACTIONS)[ResponseActionKey]][]).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}{v.destructive ? " (needs approval)" : ""}</option>
                ))}
              </Select>
            </div>
            {def.destructive ? (
              <p className="rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn">
                This is a destructive action. It will not run until a human with approval rights (SOC Manager) approves it in Approvals. Requests expire after 24 hours.
              </p>
            ) : null}
            {needsAsset ? (
              <div className="text-sm">
                <span className="text-xs font-medium text-muted">Target asset</span>
                <div className={assetId ? "" : "text-danger"}>{assetName ?? "This alert has no resolved asset, so asset actions cannot run."}</div>
              </div>
            ) : null}
            {action === "kill_process" ? (
              <div>
                <Label htmlFor="ra-proc">Process (name or PID)</Label>
                <Input id="ra-proc" required value={proc} onChange={(e) => setProc(e.target.value)} className="font-mono" />
              </div>
            ) : null}
            {def.target === "asset+ip" ? (
              <div>
                <Label htmlFor="ra-ip">IP address to block</Label>
                <Input id="ra-ip" required value={ip} onChange={(e) => setIp(e.target.value)} className="font-mono" />
              </div>
            ) : null}
            {def.target === "identity" ? (
              <div>
                <Label htmlFor="ra-ident">Identity</Label>
                <Input id="ra-ident" required value={ident} onChange={(e) => setIdent(e.target.value)} />
              </div>
            ) : null}
            {def.target === "observable" ? (
              <div>
                <Label htmlFor="ra-ioc">Indicator</Label>
                <Input id="ra-ioc" required list="ra-ioc-options" value={ioc} onChange={(e) => setIoc(e.target.value)} className="font-mono" />
                <datalist id="ra-ioc-options">
                  {observables.map((o) => <option key={`${o.type}:${o.value}`} value={o.value}>{o.type}</option>)}
                </datalist>
              </div>
            ) : null}
            <div>
              <Label htmlFor="ra-reason">Reason (required, recorded in the audit log)</Label>
              <Textarea id="ra-reason" required minLength={5} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why this action is needed and what evidence supports it" />
            </div>
            <ActionError error={error} />
            <div className="flex justify-end">
              <Button type="submit" disabled={pending || (needsAsset && !assetId)}>{def.destructive ? "Request approval" : "Request action"}</Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
