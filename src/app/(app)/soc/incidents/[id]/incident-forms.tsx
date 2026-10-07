"use client";
import { Plus } from "lucide-react";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { addIncidentEvidence, addIncidentNote, addIncidentTask, addIncidentTimelineEvent, saveIncidentCase, setIncidentTaskDone, ungroupIncidentAlerts } from "../actions";

type CaseFields = {
  status: string;
  severity: string;
  ownerId: string | null;
  description: string | null;
  containment: string | null;
  remediation: string | null;
  rootCause: string | null;
  lessonsLearned: string | null;
};

const NARRATIVE: [keyof CaseFields, string, string][] = [
  ["description", "Description", "What happened and who is affected"],
  ["containment", "Containment", "Steps taken to stop the spread"],
  ["remediation", "Remediation", "Eradication and recovery work"],
  ["rootCause", "Root cause", "How the attacker got in or why the control failed"],
  ["lessonsLearned", "Lessons learned", "What changes as a result"],
];

export function CaseForm({ incidentId, initial, statuses, severities, owners, canClose, editable }: {
  incidentId: string;
  initial: CaseFields;
  statuses: readonly string[];
  severities: readonly string[];
  owners: { id: string; name: string }[];
  canClose: boolean;
  editable: boolean;
}) {
  const [v, setV] = useState(initial);
  const [saved, setSaved] = useState(false);
  const { pending, error, run } = useAction();
  const set = (k: keyof CaseFields, val: string | null) => {
    setSaved(false);
    setV((p) => ({ ...p, [k]: val }));
  };
  const changed = Object.fromEntries(Object.entries(v).filter(([k, val]) => (val ?? "") !== (initial[k as keyof CaseFields] ?? ""))) as Partial<CaseFields>;
  const dirty = Object.keys(changed).length > 0;

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => saveIncidentCase(incidentId, changed as Parameters<typeof saveIncidentCase>[1]), () => setSaved(true));
      }}
    >
      <fieldset disabled={!editable || pending} className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <div>
            <Label htmlFor="case-status">Status</Label>
            <Select id="case-status" value={v.status} onChange={(e) => set("status", e.target.value)}>
              {statuses.map((s) => (
                <option key={s} value={s} disabled={s === "CLOSED" && !canClose && initial.status !== "CLOSED"}>{s.replaceAll("_", " ")}</option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="case-severity">Severity</Label>
            <Select id="case-severity" value={v.severity} onChange={(e) => set("severity", e.target.value)}>
              {severities.map((s) => <option key={s} value={s}>{s[0]!.toUpperCase() + s.slice(1)}</option>)}
            </Select>
          </div>
          <div>
            <Label htmlFor="case-owner">Owner</Label>
            <Select id="case-owner" value={v.ownerId ?? ""} onChange={(e) => set("ownerId", e.target.value || null)}>
              <option value="">Unowned</option>
              {owners.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </Select>
          </div>
        </div>
        {NARRATIVE.map(([key, label, placeholder]) => (
          <div key={key}>
            <Label htmlFor={`case-${key}`}>{label}</Label>
            <Textarea id={`case-${key}`} rows={key === "description" ? 4 : 3} value={v[key] ?? ""} onChange={(e) => set(key, e.target.value)} placeholder={placeholder} />
          </div>
        ))}
      </fieldset>
      {editable ? (
        <div className="flex items-center justify-end gap-3">
          <ActionError error={error} />
          {saved && !dirty ? <span role="status" className="text-xs text-ok">Saved</span> : null}
          <Button type="submit" disabled={pending || !dirty}>Save case</Button>
        </div>
      ) : null}
    </form>
  );
}

export function TimelineEventForm({ incidentId }: { incidentId: string }) {
  const [open, setOpen] = useState(false);
  const [when, setWhen] = useState("");
  const [title, setTitle] = useState("");
  const [detail, setDetail] = useState("");
  const { pending, error, run } = useAction();

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="secondary"><Plus /> Add analyst event</Button>
      </DialogTrigger>
      <DialogContent title="Add analyst event" description="Record something that happened, such as a call with the customer or a finding from manual investigation.">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            // datetime-local is the analyst's local time; send an absolute instant.
            const occurredAt = (when ? new Date(when) : new Date()).toISOString();
            run(() => addIncidentTimelineEvent(incidentId, { occurredAt, title, detail }), () => {
              setOpen(false);
              setWhen("");
              setTitle("");
              setDetail("");
            });
          }}
        >
          <div>
            <Label htmlFor="tl-when">When (leave blank for now)</Label>
            <Input id="tl-when" type="datetime-local" value={when} onChange={(e) => setWhen(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="tl-title">What happened</Label>
            <Input id="tl-title" required maxLength={300} value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="tl-detail">Detail</Label>
            <Textarea id="tl-detail" value={detail} onChange={(e) => setDetail(e.target.value)} />
          </div>
          <ActionError error={error} />
          <div className="flex justify-end"><Button type="submit" disabled={pending}>Add to timeline</Button></div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function NoteForm({ incidentId }: { incidentId: string }) {
  const [body, setBody] = useState("");
  const [visibility, setVisibility] = useState<"internal" | "customer">("internal");
  const { pending, error, run } = useAction();

  return (
    <form
      className="space-y-2"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => addIncidentNote(incidentId, body, visibility), () => setBody(""));
      }}
    >
      <Label htmlFor="note-body" className="sr-only">Note</Label>
      <Textarea id="note-body" required value={body} onChange={(e) => setBody(e.target.value)} placeholder="Add a note" />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div role="radiogroup" aria-label="Note visibility" className="inline-flex rounded-md border border-border p-0.5 text-xs">
          {(["internal", "customer"] as const).map((vis) => (
            <button
              key={vis}
              type="button"
              role="radio"
              aria-checked={visibility === vis}
              onClick={() => setVisibility(vis)}
              className={cn("rounded px-2.5 py-1", visibility === vis ? (vis === "customer" ? "bg-warn/15 text-warn" : "bg-surface-2 text-fg") : "text-muted hover:text-fg")}
            >
              {vis === "internal" ? "Internal (SOC only)" : "Customer-visible"}
            </button>
          ))}
        </div>
        <Button type="submit" size="sm" disabled={pending}>Add note</Button>
      </div>
      {visibility === "customer" ? <p className="text-xs text-warn">The customer will see this note in their portal.</p> : null}
      <ActionError error={error} />
    </form>
  );
}

export function TaskList({ incidentId, tasks, editable }: { incidentId: string; tasks: { id: string; title: string; done: boolean }[]; editable: boolean }) {
  const [title, setTitle] = useState("");
  const { pending, error, run } = useAction();

  return (
    <div className="space-y-3">
      {tasks.length === 0 ? <p className="text-sm text-muted">No tasks yet.</p> : (
        <ul className="space-y-1.5">
          {tasks.map((t) => (
            <li key={t.id} className="flex items-start gap-2 text-sm">
              <Checkbox
                id={`task-${t.id}`}
                className="mt-0.5"
                checked={t.done}
                disabled={!editable || pending}
                onCheckedChange={(c) => run(() => setIncidentTaskDone(incidentId, t.id, c === true))}
              />
              <label htmlFor={`task-${t.id}`} className={cn(t.done && "text-faint line-through")}>{t.title}</label>
            </li>
          ))}
        </ul>
      )}
      {editable ? (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            run(() => addIncidentTask(incidentId, title), () => setTitle(""));
          }}
        >
          <Label htmlFor="task-new" className="sr-only">New task</Label>
          <Input id="task-new" required maxLength={300} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Add a task" className="h-8" />
          <Button type="submit" size="sm" variant="secondary" disabled={pending}>Add</Button>
        </form>
      ) : null}
      <ActionError error={error} />
    </div>
  );
}

/** Removes automatically grouped alerts from the incident; grouping then leaves them alone. */
export function UngroupButton({ incidentId, alertIds, label }: { incidentId: string; alertIds?: string[]; label: string }) {
  const { pending, error, run } = useAction();
  return (
    <span className="inline-flex flex-col items-end gap-1">
      <Button type="button" size="sm" variant="ghost" disabled={pending} onClick={() => run(() => ungroupIncidentAlerts(incidentId, alertIds))}>{label}</Button>
      <ActionError error={error} />
    </span>
  );
}

const EVIDENCE_KINDS = ["file", "memory_image", "disk_image", "log_export", "pcap", "screenshot", "email", "other"];

export function EvidenceForm({ incidentId }: { incidentId: string }) {
  const [open, setOpen] = useState(false);
  const empty = { name: "", kind: "file", sha256: "", storageUri: "", description: "" };
  const [v, setV] = useState(empty);
  const { pending, error, run } = useAction();
  const set = (k: keyof typeof empty) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => setV((p) => ({ ...p, [k]: e.target.value }));

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="secondary"><Plus /> Add evidence</Button>
      </DialogTrigger>
      <DialogContent title="Add evidence" description="Records chain-of-custody metadata. Store the artefact itself in the evidence store and reference it here.">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            run(() => addIncidentEvidence(incidentId, v), () => {
              setOpen(false);
              setV(empty);
            });
          }}
        >
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="ev-name">Name</Label>
              <Input id="ev-name" required value={v.name} onChange={set("name")} />
            </div>
            <div>
              <Label htmlFor="ev-kind">Kind</Label>
              <Select id="ev-kind" value={v.kind} onChange={set("kind")}>
                {EVIDENCE_KINDS.map((k) => <option key={k} value={k}>{k.replaceAll("_", " ")}</option>)}
              </Select>
            </div>
          </div>
          <div>
            <Label htmlFor="ev-sha">SHA-256</Label>
            <Input id="ev-sha" value={v.sha256} onChange={set("sha256")} pattern="[0-9a-fA-F]{64}" title="64 hexadecimal characters" className="font-mono text-xs" />
          </div>
          <div>
            <Label htmlFor="ev-uri">Storage URI</Label>
            <Input id="ev-uri" value={v.storageUri} onChange={set("storageUri")} placeholder="s3://evidence/…" className="font-mono text-xs" />
          </div>
          <div>
            <Label htmlFor="ev-desc">Description</Label>
            <Textarea id="ev-desc" value={v.description} onChange={set("description")} />
          </div>
          <ActionError error={error} />
          <div className="flex justify-end"><Button type="submit" disabled={pending}>Add evidence</Button></div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
