"use client";
import { useState } from "react";
import { ToggleSwitch } from "@/components/soc/toggle-switch";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Input, Label, Textarea } from "@/components/ui/input";
import { addMemoryNote, approveRule, expireRule, extendRule, rejectRule, removeMemoryNote, saveHermesRetention, setHermesSwitch, undoAction } from "./actions";
import { MEMORY_RETENTION_MAX_DAYS } from "@/lib/tuning/memory";

const plural = (n: number | undefined, one: string) => `${n ?? 0} ${one}${n === 1 ? "" : "s"}`;

/** Approve / reject a proposal; extend / expire a live rule. Every one is audited. */
export function RuleControls({ id, status }: { id: string; status: string }) {
  const { pending, error, run } = useAction();
  const [days, setDays] = useState(30);
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-1.5">
        {status === "proposed" ? (
          <>
            <Button size="sm" disabled={pending} onClick={() => run(() => approveRule(id), undefined, { success: (d) => `Rule approved. ${plural(d?.moved, "alert")} moved to the passive lane.` })}>Approve</Button>
            <Button size="sm" variant="secondary" disabled={pending} onClick={() => run(() => rejectRule(id), undefined, { success: "Proposal rejected" })}>Reject</Button>
          </>
        ) : null}
        {status === "active" ? (
          <>
            <label className="sr-only" htmlFor={`extend-${id}`}>Extend by days from today</label>
            <Input id={`extend-${id}`} type="number" min={1} max={180} value={days} onChange={(e) => setDays(Number(e.target.value))} className="h-8 w-16 text-xs" />
            <Button size="sm" variant="secondary" disabled={pending} onClick={() => run(() => extendRule(id, days), undefined, { success: `Rule now expires ${days} days from today` })}>Extend</Button>
          </>
        ) : null}
        {status === "active" || status === "proposed" ? (
          <Button size="sm" variant="ghost" disabled={pending} onClick={() => run(() => expireRule(id), undefined, { success: "Rule expired. It no longer matches new alerts." })}>Expire now</Button>
        ) : null}
      </div>
      <ActionError error={error} />
    </div>
  );
}

export function UndoButton({ id, kind, label = "Undo" }: { id: string; kind: string; label?: string }) {
  const { pending, error, run } = useAction();
  if (kind !== "close" && kind !== "noise_rule") return null;
  return (
    <div className="space-y-1">
      <Button
        size="sm"
        variant="secondary"
        disabled={pending}
        onClick={() => run(() => undoAction(id), undefined, { success: (d) => (kind === "close" ? `${plural(d?.restored, "alert")} reopened as new` : `Rule expired; ${plural(d?.restored, "alert")} back in the active queue`) })}
      >
        {label}
      </Button>
      <ActionError error={error} />
    </div>
  );
}

export function HermesSwitch({ enabled, canControl }: { enabled: boolean; canControl: boolean }) {
  const { pending, error, run } = useAction();
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-3">
        <ToggleSwitch
          label="Allow Hermes to act"
          checked={enabled}
          disabled={!canControl || pending}
          onChange={(v) => run(() => setHermesSwitch(v), undefined, { success: v ? "Hermes may now act within its guardrails" : "Hermes can no longer act; it can still read and annotate" })}
        />
        <span className="text-sm font-medium">Allow Hermes to act</span>
        <span className="text-xs text-muted">{enabled ? "On: may close low-stakes noise and create noise rules within guardrails." : "Off: reads and annotates only. Acting calls are refused."}</span>
      </div>
      {!canControl ? <p className="text-xs text-faint">Only SOC managers and platform administrators can change this.</p> : null}
      <ActionError error={error} />
    </div>
  );
}

export function AddMemoryNoteForm() {
  const { pending, error, run } = useAction();
  const [text, setText] = useState("");
  return (
    <form
      className="space-y-2"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => addMemoryNote({ text }), () => setText(""), { success: "Note added to Hermes' memory" });
      }}
    >
      <div>
        <Label htmlFor="mem-text">Lesson for Hermes (and why you know)</Label>
        <Textarea id="mem-text" required maxLength={2000} value={text} onChange={(e) => setText(e.target.value)} placeholder="e.g. Rule 5710 on backup servers is expected during the 02:00 window; never close it on domain controllers." />
      </div>
      <p className="text-[11px] text-faint">Describe patterns, not customers: notes naming hosts, addresses or email addresses are refused.</p>
      <ActionError error={error} />
      <Button type="submit" size="sm" disabled={pending}>Add note</Button>
    </form>
  );
}

export function HermesRetentionForm({ days, canControl }: { days: number; canControl: boolean }) {
  const { pending, error, run } = useAction();
  const [value, setValue] = useState(String(days));
  return (
    <form className="space-y-3" onSubmit={(e) => {
      e.preventDefault();
      run(() => saveHermesRetention(Number(value)), undefined, { success: "Hermes retention saved. Cleanup runs hourly." });
    }}>
      <p className="text-sm text-muted">Keep memories and run reports for {days} days. Reviews run hourly by default. Hermes saves lessons after each run and uses analyst feedback in future reviews.</p>
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <Label htmlFor="hermes-retention">Data retention (days)</Label>
          <Input id="hermes-retention" type="number" required min={1} max={MEMORY_RETENTION_MAX_DAYS} step={1} value={value} onChange={(e) => setValue(e.target.value)} disabled={!canControl || pending} aria-describedby="hermes-retention-help" className="w-28" />
        </div>
        <Button type="submit" size="sm" disabled={!canControl || pending || Number(value) === days}>Save retention</Button>
      </div>
      <p id="hermes-retention-help" className="text-xs text-faint">Default: 90 days. Choose 1–{MEMORY_RETENTION_MAX_DAYS} days. All memories, including analyst notes, expire from their original creation date. Older memories and reports are permanently deleted during hourly cleanup; increasing retention cannot restore them. Memory also has a 500-note limit. Action and audit history use separate retention.</p>
      {!canControl ? <p className="text-xs text-faint">Only SOC managers and platform administrators can change retention.</p> : null}
      <ActionError error={error} />
    </form>
  );
}

export function DeleteNoteButton({ id }: { id: string }) {
  const { pending, run } = useAction();
  return (
    <Button size="sm" variant="ghost" disabled={pending} onClick={() => run(() => removeMemoryNote(id), undefined, { success: "Note deleted from Hermes' memory" })}>
      Delete
    </Button>
  );
}
