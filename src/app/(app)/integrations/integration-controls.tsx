"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";
import { ToggleSwitch } from "@/components/soc/toggle-switch";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Label, Select } from "@/components/ui/input";
import type { Severity } from "@/lib/providers/types";
import { setAlertFloorAction, testIntegrationAction, updateIntegrationAction } from "./actions";

export function IntegrationToggle({ id, name, enabled, disabled }: { id: string; name: string; enabled: boolean; disabled?: boolean }) {
  const [on, setOn] = useState(enabled);
  const { pending, error, run } = useAction();
  return (
    <span className="inline-flex items-center gap-2 text-xs text-muted">
      {on ? "Enabled" : "Disabled"}
      <ToggleSwitch
        checked={on}
        disabled={disabled || pending}
        label={`${on ? "Disable" : "Enable"} ${name}`}
        onChange={(v) => {
          setOn(v);
          run(async () => {
            const res = await updateIntegrationAction(id, { enabled: v });
            if (!res.ok) setOn(!v);
            return res;
          }, undefined, { success: `${name} ${v ? "enabled" : "disabled"}` });
        }}
      />
      {error ? <span role="alert" className="text-danger" title={error}>Failed</span> : null}
    </span>
  );
}

export function TestConnection({ id }: { id: string }) {
  const router = useRouter();
  const { pending, error, run } = useAction();
  const [result, setResult] = useState<{ ok: boolean; latencyMs: number; error?: string } | null>(null);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button
        type="button"
        size="sm"
        variant="secondary"
        disabled={pending}
        onClick={() => {
          setResult(null);
          run(
            () => testIntegrationAction(id),
            (r) => {
              setResult(r ?? null);
              if (r && !r.ok) toast.error(`Connection test failed: ${r.error ?? "unknown error"}`, { duration: 8_000 });
              router.refresh();
            },
            { success: (r) => (r?.ok ? `Connection test passed (${r.latencyMs} ms)` : null) },
          );
        }}
      >
        {pending ? "Testing…" : "Test connection"}
      </Button>
      {result ? (
        <span role="status" className={result.ok ? "text-xs text-ok" : "text-xs text-danger"}>
          {result.ok ? `Connected (${result.latencyMs} ms)` : `Failed: ${result.error ?? "unknown error"}`}
        </span>
      ) : null}
      <ActionError error={error} />
    </div>
  );
}

const FLOOR_OPTIONS: { value: Severity; label: string }[] = [
  { value: "informational", label: "Keep everything (informational and up)" },
  { value: "low", label: "Ignore informational (low and up)" },
  { value: "medium", label: "Ignore low and below (medium and up)" },
  { value: "high", label: "Ignore medium and below (high and critical only)" },
  { value: "critical", label: "Critical only" },
];

/** Lowest alert severity stored from this integration. Saves on change. */
export function AlertFloor({ id, value, disabled }: { id: string; value: Severity; disabled?: boolean }) {
  const router = useRouter();
  const [floor, setFloor] = useState<Severity>(value);
  const { pending, error, run } = useAction();
  return (
    <div className="space-y-2">
      <Label htmlFor={`floor-${id}`}>Store alerts from</Label>
      <Select
        id={`floor-${id}`}
        value={floor}
        disabled={disabled || pending}
        onChange={(e) => {
          const next = e.target.value as Severity;
          const prev = floor;
          setFloor(next);
          run(
            async () => {
              const res = await setAlertFloorAction(id, next);
              if (!res.ok) setFloor(prev);
              return res;
            },
            () => router.refresh(),
            { success: "Alert floor saved. Applies from the next poll." },
          );
        }}
      >
        {FLOOR_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </Select>
      <p className="text-xs text-muted">Lower alerts are not stored in blakSOC and stay searchable in the source. Alerts already stored are not changed.</p>
      {pending ? <span className="text-xs text-muted">Saving…</span> : null}
      <ActionError error={error} />
    </div>
  );
}
