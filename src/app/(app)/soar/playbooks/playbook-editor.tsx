"use client";
import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { APPROVAL_EXPLAINER, EVENT_LABELS, FlowPreview, HumanApprovalBadge, OP_LABELS, fmtValue, isDestructive, type CatalogueEntry } from "@/components/soar/flow";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import type { PlaybookStep, PlaybookTrigger } from "@/db/schema";
import { savePlaybookAction } from "./actions";

type Op = PlaybookTrigger["conditions"][number]["op"];
type CondRow = { field: string; op: Op; value: string };
type StepRow = { key: string; id: string; action: string; name: string; params: string; when: CondRow | null; requireApproval: boolean; continueOnError: boolean };

const EVENTS = Object.keys(EVENT_LABELS) as PlaybookTrigger["event"][];
const OPS = Object.keys(OP_LABELS) as Op[];
const FIELD_SUGGESTIONS = [
  "alert.riskScore", "alert.severity", "alert.intelVerdict", "alert.attackTechniques", "alert.category", "alert.source", "alert.userName",
  "asset.criticality", "asset.exposure", "asset.kind", "asset.agentStatus", "intel.verdict",
];

function coerce(raw: string): unknown {
  const s = raw.trim();
  if (s === "true" || s === "false") return s === "true";
  if (s !== "" && /^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  return s;
}
function parseValue(op: Op, raw: string): unknown {
  return op === "in" ? raw.split(",").map((x) => x.trim()).filter(Boolean).map(coerce) : coerce(raw);
}
const toRow = (c: { field: string; op: Op; value: unknown }): CondRow => ({ field: c.field, op: c.op, value: fmtValue(c.value) });
const fromRow = (c: CondRow) => ({ field: c.field.trim(), op: c.op, value: parseValue(c.op, c.value) });

let seq = 0;
const rowKey = () => `r${++seq}`;

export type EditorPlaybook = { id?: string; tenantId: string | null; name: string; description: string | null; trigger: PlaybookTrigger; steps: PlaybookStep[] };

export function PlaybookEditor({ initial, catalogue, owners, canEdit }: { initial: EditorPlaybook; catalogue: CatalogueEntry[]; owners: { id: string | null; name: string }[]; canEdit: boolean }) {
  const router = useRouter();
  const uid = useId();
  const { pending, error, setError, run } = useAction();
  const [saved, setSaved] = useState(false);
  const [owner, setOwner] = useState(initial.tenantId ?? "");
  const [name, setName] = useState(initial.name);
  const [description, setDescription] = useState(initial.description ?? "");
  const [event, setEvent] = useState(initial.trigger.event);
  const [conds, setConds] = useState<(CondRow & { key: string })[]>(initial.trigger.conditions.map((c) => ({ ...toRow(c), key: rowKey() })));
  const [steps, setSteps] = useState<StepRow[]>(
    initial.steps.map((s) => ({
      key: rowKey(), id: s.id, action: s.action, name: s.name, params: s.params && Object.keys(s.params).length ? JSON.stringify(s.params, null, 2) : "",
      when: s.when ? toRow(s.when) : null, requireApproval: !!s.requireApproval, continueOnError: !!s.continueOnError,
    })),
  );
  const ro = !canEdit;
  const labelOf = (a: string) => catalogue.find((c) => c.key === a)?.label ?? a;

  const preview = {
    trigger: { event, conditions: conds.filter((c) => c.field.trim()).map(fromRow) },
    steps: steps.map((s) => ({ id: s.id, action: s.action, name: s.name || labelOf(s.action), when: s.when?.field ? fromRow(s.when) : undefined, requireApproval: s.requireApproval })),
  };

  const patchStep = (key: string, p: Partial<StepRow>) => { setSaved(false); setSteps((xs) => xs.map((s) => (s.key === key ? { ...s, ...p } : s))); };
  const patchCond = (key: string, p: Partial<CondRow>) => { setSaved(false); setConds((xs) => xs.map((c) => (c.key === key ? { ...c, ...p } : c))); };
  const move = (i: number, d: -1 | 1) => setSteps((xs) => { const n = [...xs]; [n[i], n[i + d]] = [n[i + d]!, n[i]!]; return n; });
  const addStep = () => {
    const action = catalogue[0]!.key;
    let n = steps.length + 1;
    while (steps.some((s) => s.id === `step-${n}`)) n++;
    setSteps((xs) => [...xs, { key: rowKey(), id: `step-${n}`, action, name: labelOf(action), params: "", when: null, requireApproval: false, continueOnError: false }]);
  };

  function save() {
    setSaved(false);
    const built: PlaybookStep[] = [];
    for (const s of steps) {
      let params: Record<string, unknown> | undefined;
      if (s.params.trim()) {
        try {
          params = JSON.parse(s.params);
        } catch {
          setError(`Step "${s.name || s.id}": parameters must be valid JSON.`);
          return;
        }
      }
      built.push({ id: s.id.trim(), action: s.action, name: s.name.trim(), params, when: s.when?.field.trim() ? fromRow(s.when) : undefined, requireApproval: s.requireApproval || undefined, continueOnError: s.continueOnError || undefined });
    }
    const ids = built.map((s) => s.id);
    if (new Set(ids).size !== ids.length) return setError("Step IDs must be unique.");
    if (!built.length) return setError("Add at least one step.");
    run(
      () => savePlaybookAction({ id: initial.id, tenantId: owner || null, name, description, trigger: { event, conditions: conds.filter((c) => c.field.trim()).map(fromRow) }, steps: built }),
      (id) => {
        setSaved(true);
        if (!initial.id && id) router.push(`/soar/playbooks/${id}`);
        else router.refresh();
      },
    );
  }

  return (
    <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); save(); }}>
      <datalist id={`${uid}-fields`}>{FIELD_SUGGESTIONS.map((f) => <option key={f} value={f} />)}</datalist>

      <Card>
        <CardHeader><CardTitle>Flow</CardTitle></CardHeader>
        <CardContent><FlowPreview trigger={preview.trigger} steps={preview.steps} catalogue={catalogue} /></CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Details</CardTitle></CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <div>
            <Label htmlFor={`${uid}-name`}>Name</Label>
            <Input id={`${uid}-name`} value={name} onChange={(e) => { setSaved(false); setName(e.target.value); }} required maxLength={160} disabled={ro} />
          </div>
          <div>
            <Label htmlFor={`${uid}-owner`}>Scope</Label>
            <Select id={`${uid}-owner`} value={owner} onChange={(e) => setOwner(e.target.value)} disabled={ro || !!initial.id}>
              {initial.id ? <option value={owner}>{owner ? owners.find((o) => o.id === owner)?.name ?? "Customer" : "Global (all customers)"}</option> : owners.map((o) => <option key={o.id ?? "global"} value={o.id ?? ""}>{o.name}</option>)}
            </Select>
            {initial.id ? <p className="mt-1 text-[11px] text-faint">Scope is fixed after creation.</p> : null}
          </div>
          <div className="md:col-span-2">
            <Label htmlFor={`${uid}-desc`}>Description</Label>
            <Textarea id={`${uid}-desc`} value={description} onChange={(e) => { setSaved(false); setDescription(e.target.value); }} rows={2} maxLength={2000} disabled={ro} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Trigger</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <div className="max-w-xs">
            <Label htmlFor={`${uid}-event`}>Event</Label>
            <Select id={`${uid}-event`} value={event} onChange={(e) => { setSaved(false); setEvent(e.target.value as PlaybookTrigger["event"]); }} disabled={ro}>
              {EVENTS.map((ev) => <option key={ev} value={ev}>{EVENT_LABELS[ev]} ({ev})</option>)}
            </Select>
          </div>
          <fieldset className="space-y-2">
            <legend className="mb-1 text-xs font-medium text-muted">Conditions (all must hold)</legend>
            {conds.length === 0 ? <p className="text-sm text-faint">No conditions: runs on every {EVENT_LABELS[event].toLowerCase()} event.</p> : null}
            {conds.map((c, i) => (
              <ConditionRow key={c.key} idp={`${uid}-c${i}`} listId={`${uid}-fields`} value={c} disabled={ro} onChange={(p) => patchCond(c.key, p)} onRemove={() => setConds((xs) => xs.filter((x) => x.key !== c.key))} />
            ))}
            {!ro ? <Button type="button" variant="ghost" size="sm" onClick={() => setConds((xs) => [...xs, { key: rowKey(), field: "", op: "gte", value: "" }])}><Plus />Add condition</Button> : null}
          </fieldset>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Steps</CardTitle>
          <span className="text-xs text-muted">Run in order. Destructive steps always pause for approval.</span>
        </CardHeader>
        <ol className="divide-y divide-border">
          {steps.map((s, i) => {
            const destructive = isDestructive(s.action, catalogue);
            const idp = `${uid}-s${i}`;
            return (
              <li key={s.key} className="space-y-3 px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="num w-6 text-sm font-semibold text-faint">{i + 1}.</span>
                  <span className="text-sm font-medium">{s.name || labelOf(s.action)}</span>
                  {destructive ? <HumanApprovalBadge /> : s.requireApproval || s.action === "approval.request" ? <span className="rounded bg-warn/15 px-1.5 py-0.5 text-[11px] text-warn">Approval gate</span> : null}
                  {!ro ? (
                    <span className="ml-auto flex items-center gap-1">
                      <Button type="button" variant="ghost" size="icon" aria-label={`Move step ${i + 1} up`} disabled={i === 0} onClick={() => move(i, -1)}><ArrowUp /></Button>
                      <Button type="button" variant="ghost" size="icon" aria-label={`Move step ${i + 1} down`} disabled={i === steps.length - 1} onClick={() => move(i, 1)}><ArrowDown /></Button>
                      <Button type="button" variant="ghost" size="icon" aria-label={`Remove step ${i + 1}`} onClick={() => setSteps((xs) => xs.filter((x) => x.key !== s.key))}><Trash2 /></Button>
                    </span>
                  ) : null}
                </div>
                <div className="grid gap-3 md:grid-cols-[1fr_1fr_10rem]">
                  <div>
                    <Label htmlFor={`${idp}-action`}>Action</Label>
                    <Select id={`${idp}-action`} value={s.action} disabled={ro} onChange={(e) => { const a = e.target.value; patchStep(s.key, { action: a, name: !s.name || s.name === labelOf(s.action) ? labelOf(a) : s.name }); }}>
                      <optgroup label="Automated">{catalogue.filter((c) => !c.destructive).map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}</optgroup>
                      <optgroup label="Containment (approval required)">{catalogue.filter((c) => c.destructive).map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}</optgroup>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor={`${idp}-name`}>Step name</Label>
                    <Input id={`${idp}-name`} value={s.name} required maxLength={160} disabled={ro} onChange={(e) => patchStep(s.key, { name: e.target.value })} />
                  </div>
                  <div>
                    <Label htmlFor={`${idp}-id`}>Step ID</Label>
                    <Input id={`${idp}-id`} value={s.id} required pattern="[A-Za-z0-9_\-]+" maxLength={64} className="font-mono text-xs" disabled={ro} onChange={(e) => patchStep(s.key, { id: e.target.value })} />
                  </div>
                </div>
                {destructive ? <p className="text-xs text-warn/90">{APPROVAL_EXPLAINER}</p> : null}
                <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                  <label className="inline-flex items-center gap-2">
                    <Checkbox checked={destructive || s.requireApproval} disabled={ro || destructive} onCheckedChange={(v) => patchStep(s.key, { requireApproval: v === true })} aria-label="Require approval" />
                    Require approval{destructive ? " (locked on)" : ""}
                  </label>
                  <label className="inline-flex items-center gap-2">
                    <Checkbox checked={s.continueOnError} disabled={ro} onCheckedChange={(v) => patchStep(s.key, { continueOnError: v === true })} aria-label="Continue on error" />
                    Continue on error
                  </label>
                  <label className="inline-flex items-center gap-2">
                    <Checkbox checked={!!s.when} disabled={ro} onCheckedChange={(v) => patchStep(s.key, { when: v === true ? { field: "", op: "eq", value: "" } : null })} aria-label="Only run when a condition holds" />
                    Only run when…
                  </label>
                </div>
                {s.when ? <ConditionRow idp={`${idp}-when`} listId={`${uid}-fields`} value={s.when} disabled={ro} onChange={(p) => patchStep(s.key, { when: { ...s.when!, ...p } })} /> : null}
                <details className="text-sm" open={!!s.params}>
                  <summary className="cursor-pointer text-xs text-muted hover:text-fg">Parameters (optional)</summary>
                  <Label htmlFor={`${idp}-params`} className="sr-only">Parameters JSON</Label>
                  <Textarea id={`${idp}-params`} value={s.params} disabled={ro} rows={3} className="mt-2 font-mono text-xs" placeholder='{"title": "Suspicious sign-in", "message": "…"}' onChange={(e) => patchStep(s.key, { params: e.target.value })} />
                </details>
              </li>
            );
          })}
        </ol>
        {!ro ? <div className="border-t border-border px-4 py-3"><Button type="button" variant="secondary" size="sm" onClick={addStep}><Plus />Add step</Button></div> : null}
      </Card>

      {!ro ? (
        <div className="flex items-center gap-3">
          <Button type="submit" disabled={pending}>{pending ? "Saving…" : initial.id ? "Save new version" : "Create playbook"}</Button>
          {saved ? <span className="text-sm text-ok" role="status">Saved.</span> : null}
          <ActionError error={error} />
        </div>
      ) : (
        <p className="text-sm text-muted">You can view this playbook but not edit it.</p>
      )}
    </form>
  );
}

function ConditionRow({ idp, listId, value, disabled, onChange, onRemove }: { idp: string; listId: string; value: CondRow; disabled?: boolean; onChange: (p: Partial<CondRow>) => void; onRemove?: () => void }) {
  return (
    <div className="grid items-end gap-2 sm:grid-cols-[1fr_10rem_1fr_auto]">
      <div>
        <Label htmlFor={`${idp}-f`}>Field</Label>
        <Input id={`${idp}-f`} list={listId} value={value.field} placeholder="alert.riskScore" className="font-mono text-xs" disabled={disabled} onChange={(e) => onChange({ field: e.target.value })} />
      </div>
      <div>
        <Label htmlFor={`${idp}-o`}>Operator</Label>
        <Select id={`${idp}-o`} value={value.op} disabled={disabled} onChange={(e) => onChange({ op: e.target.value as Op })}>
          {OPS.map((o) => <option key={o} value={o}>{OP_LABELS[o]}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor={`${idp}-v`}>Value{value.op === "in" ? " (comma-separated)" : ""}</Label>
        <Input id={`${idp}-v`} value={value.value} placeholder={value.op === "in" ? "high, critical" : "80"} disabled={disabled} onChange={(e) => onChange({ value: e.target.value })} />
      </div>
      {onRemove && !disabled ? <Button type="button" variant="ghost" size="icon" aria-label="Remove condition" onClick={onRemove}><Trash2 /></Button> : <span />}
    </div>
  );
}
