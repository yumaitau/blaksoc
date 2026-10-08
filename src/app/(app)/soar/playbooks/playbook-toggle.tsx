"use client";
import { useState } from "react";
import { ToggleSwitch } from "@/components/soc/toggle-switch";
import { useAction } from "@/components/soc/use-action";
import { setPlaybookEnabledAction } from "./actions";

export function PlaybookToggle({ id, name, enabled, disabled }: { id: string; name: string; enabled: boolean; disabled?: boolean }) {
  const [on, setOn] = useState(enabled);
  const { pending, error, run } = useAction();
  return (
    <span className="inline-flex items-center gap-2">
      <ToggleSwitch
        checked={on}
        disabled={disabled || pending}
        label={`${on ? "Disable" : "Enable"} ${name}`}
        onChange={(v) => {
          setOn(v);
          run(async () => {
            const res = await setPlaybookEnabledAction(id, v);
            if (!res.ok) setOn(!v);
            return res;
          }, undefined, { success: `Playbook ${name} ${v ? "enabled" : "disabled"}` });
        }}
      />
      {error ? <span role="alert" className="text-[11px] text-danger" title={error}>Failed</span> : null}
    </span>
  );
}
