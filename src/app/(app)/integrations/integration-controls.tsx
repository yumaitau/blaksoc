"use client";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ToggleSwitch } from "@/components/soc/toggle-switch";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { testIntegrationAction, updateIntegrationAction } from "./actions";

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
          });
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
          run(() => testIntegrationAction(id), (r) => { setResult(r ?? null); router.refresh(); });
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
