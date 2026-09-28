"use client";
import Link from "next/link";
import { useId, useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Label, Select } from "@/components/ui/input";
import { runPlaybookAction } from "../actions";

export function RunManually({ playbookId, alerts }: { playbookId: string; alerts: { id: string; label: string }[] }) {
  const uid = useId();
  const [alertId, setAlertId] = useState(alerts[0]?.id ?? "");
  const [runId, setRunId] = useState<string | null>(null);
  const { pending, error, run } = useAction();
  if (!alerts.length) return <p className="text-sm text-muted">No recent alerts in this playbook&apos;s scope to run against.</p>;
  return (
    <form
      className="flex flex-wrap items-end gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        setRunId(null);
        run(() => runPlaybookAction(playbookId, alertId), (id) => setRunId(id ?? null));
      }}
    >
      <div className="min-w-0 flex-1">
        <Label htmlFor={`${uid}-alert`}>Alert</Label>
        <Select id={`${uid}-alert`} value={alertId} onChange={(e) => setAlertId(e.target.value)}>
          {alerts.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
        </Select>
      </div>
      <Button type="submit" variant="secondary" disabled={pending || !alertId}>{pending ? "Starting…" : "Run now"}</Button>
      {runId ? <span role="status" className="text-sm text-ok">Run started. <Link href={`/soar/runs/${runId}`} className="text-accent hover:underline">View run →</Link></span> : null}
      <div className="basis-full"><ActionError error={error} /></div>
    </form>
  );
}
