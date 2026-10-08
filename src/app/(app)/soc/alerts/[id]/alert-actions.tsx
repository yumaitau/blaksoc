"use client";
import { BellOff, FilePlus2, ShieldAlert, Undo2, UserCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { RESPONSE_ACTIONS, type ResponseActionKey } from "@/lib/soar/actions";
import { assignAlertsToMe, createIncidentFromSelection, markAlertAsNoise, moveToActiveQueue, requestAlertResponse, setAlertStatus } from "../actions";

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
            <Select id="alert-status" className="h-8 w-44 text-xs" value={status} disabled={pending} onChange={(e) => {
              const next = e.target.value;
              run(() => setAlertStatus([alertId], next), undefined, { success: `Alert marked ${next.replaceAll("_", " ")}` });
            }}>
              {statuses.map((s) => <option key={s} value={s}>{s.replaceAll("_", " ")}</option>)}
            </Select>
            {!assignedToMe ? (
              <Button size="sm" variant="secondary" disabled={pending} onClick={() => run(() => assignAlertsToMe([alertId]), undefined, { success: "Alert assigned to you" })}>
                <UserCheck /> Assign to me
              </Button>
            ) : null}
          </>
        ) : null}
        {canEscalate && !hasIncident ? (
          <Button size="sm" variant="secondary" disabled={pending} onClick={() => run(() => createIncidentFromSelection([alertId], [tenantId]), (d) => d && router.push(`/soc/incidents/${d.id}`), { success: "Alert escalated to a new incident" })}>
            <FilePlus2 /> Escalate to incident
          </Button>
        ) : null}
      </div>
      <ActionError error={error} />
    </div>
  );
}

/** Passive → active queue; for the alert page and each row of the passive tab. */
export function MoveToActiveButton({ ids, compact }: { ids: string[]; compact?: boolean }) {
  const { pending, run } = useAction();
  return (
    <Button size="sm" variant="secondary" className={compact ? "h-7 px-2 text-xs" : undefined} disabled={pending} onClick={() => run(() => moveToActiveQueue(ids), undefined, { success: (n) => `${n ?? ids.length} alert${(n ?? ids.length) === 1 ? "" : "s"} moved to the active queue` })}>
      <Undo2 /> Move to active queue
    </Button>
  );
}

/**
 * "Mark as noise…": creates an active noise rule (this host or every host of the customer) that keeps matching
 * alerts out of the queue until it expires. Nothing is closed; the alerts stay stored and searchable.
 */
export function MarkAsNoiseDialog({ alertId, ruleId, source, hostLabel, title }: { alertId: string; ruleId: string; source: string; hostLabel: string | null; title: string }) {
  const [open, setOpen] = useState(false);
  const [scope, setScope] = useState<"host" | "tenant">(hostLabel ? "host" : "tenant");
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(30);
  const [pattern, setPattern] = useState("");
  const { pending, error, run } = useAction();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    run(
      () => markAlertAsNoise({ alertId, scope, reason, expiresInDays: days, titlePattern: pattern || undefined }),
      () => setOpen(false),
      { success: (d) => `Noise rule created. ${d?.moved ?? 0} alert${d?.moved === 1 ? "" : "s"} moved to the passive lane.` },
    );
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline"><BellOff /> Mark as noise…</Button>
      </DialogTrigger>
      <DialogContent title="Mark as noise" description={`Alerts from ${source} rule ${ruleId} that match go to the passive lane: stored, searchable and on their asset, but out of the queue. Nothing is closed.`}>
        <form className="space-y-3" onSubmit={submit}>
          <fieldset className="space-y-1.5">
            <legend className="text-xs font-medium text-muted">Applies to</legend>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="noise-scope" checked={scope === "host"} disabled={!hostLabel} onChange={() => setScope("host")} />
              This host only{hostLabel ? <span className="text-muted">({hostLabel})</span> : <span className="text-faint">(host unknown)</span>}
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" name="noise-scope" checked={scope === "tenant"} onChange={() => setScope("tenant")} />
              Every host of this customer
            </label>
          </fieldset>
          <div>
            <Label htmlFor="noise-pattern">Title pattern (optional)</Label>
            <Input id="noise-pattern" value={pattern} maxLength={200} onChange={(e) => setPattern(e.target.value)} placeholder={`e.g. ${title.split(" ").slice(0, 2).join(" ")}*  (blank: any title)`} />
            <p className="mt-1 text-[11px] text-faint">Case-insensitive; * matches anything. Must match this alert&apos;s title.</p>
          </div>
          <div>
            <Label htmlFor="noise-days">Expires after (days)</Label>
            <Input id="noise-days" type="number" min={1} max={180} required value={days} onChange={(e) => setDays(Number(e.target.value))} />
            <p className="mt-1 text-[11px] text-faint">Every noise rule expires: 30 days by default, 180 at most.</p>
          </div>
          <div>
            <Label htmlFor="noise-reason">Reason (required, shown on every alert it affects and recorded in the audit log)</Label>
            <Textarea id="noise-reason" required minLength={5} maxLength={1000} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Nightly backup job's service account; confirmed with the customer" />
          </div>
          <p className="text-xs text-muted">Matching open alerts (new or triaging) move to the passive lane now. Alerts with a threat-intel match always stay in the queue.</p>
          <ActionError error={error} />
          <div className="flex justify-end">
            <Button type="submit" disabled={pending}>Create noise rule</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
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
    run(
      () => requestAlertResponse({ alertId, tenantId, action, reason, target }),
      () => {
        setOpen(false);
        setReason("");
      },
      { success: (d) => `${def.label} requested. ${d?.needsApproval ? "It waits for a SOC Manager's approval before anything runs." : "It is queued to run."}` },
    );
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline"><ShieldAlert /> Request response action</Button>
      </DialogTrigger>
      <DialogContent title="Request response action" description="Actions run against the customer's real systems through the owning integration.">
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
      </DialogContent>
    </Dialog>
  );
}
