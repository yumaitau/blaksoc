"use client";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { verifyAuditAction } from "../actions";

export function VerifyIntegrity() {
  const { pending, error, run } = useAction();
  const [r, setR] = useState<{ ok: boolean; checked: number; firstBadId: number | null } | null>(null);
  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button type="button" size="sm" variant="secondary" disabled={pending} onClick={() => run(() => verifyAuditAction(), (d) => setR(d ?? null))}>
        {pending ? "Verifying…" : "Verify integrity"}
      </Button>
      {r ? (
        r.ok ? (
          <span role="status" className="flex items-center gap-1.5 text-sm text-ok"><ShieldCheck className="size-4" />Chain intact · {r.checked.toLocaleString("en-AU")} entries checked</span>
        ) : (
          <span role="alert" className="flex items-center gap-1.5 text-sm text-danger">
            <ShieldAlert className="size-4" />Chain broken at entry #{r.firstBadId} · {r.checked.toLocaleString("en-AU")} checked. Treat entries from that point as untrusted and escalate.
          </span>
        )
      ) : null}
      <ActionError error={error} />
    </div>
  );
}
