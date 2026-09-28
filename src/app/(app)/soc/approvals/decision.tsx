"use client";
import { Check, X } from "lucide-react";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Label, Textarea } from "@/components/ui/input";
import { decide } from "./actions";

export function Decision({ approvalId, destructive }: { approvalId: string; destructive: boolean }) {
  const [note, setNote] = useState("");
  const { pending, error, setError, run } = useAction();

  function submit(decision: "APPROVED" | "REJECTED") {
    if (decision === "REJECTED" && !note.trim()) {
      setError("Add a note explaining why this is rejected.");
      return;
    }
    run(() => decide({ approvalId, decision, note }));
  }

  return (
    <div className="space-y-2">
      <Label htmlFor={`note-${approvalId}`}>Decision note (required to reject)</Label>
      <Textarea id={`note-${approvalId}`} rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Recorded in the audit log and incident timeline" />
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant={destructive ? "danger" : "default"} disabled={pending} onClick={() => submit("APPROVED")}>
          <Check /> {destructive ? "Approve destructive action" : "Approve"}
        </Button>
        <Button size="sm" variant="secondary" disabled={pending} onClick={() => submit("REJECTED")}>
          <X /> Reject
        </Button>
      </div>
      <ActionError error={error} />
    </div>
  );
}
