"use client";
import Link from "next/link";
import { useState } from "react";
import { RiskScore } from "@/components/soc/indicators";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { markVulns } from "./actions";

export type Instance = {
  id: string;
  assetId: string;
  assetName: string;
  criticality: number;
  exposure: string;
  packageName: string | null;
  packageVersion: string | null;
  fixedVersion: string | null;
  status: string;
  priorityScore: number;
  lastSeen: string;
};

const STATUS_VARIANT: Record<string, "warn" | "ok" | "default"> = { open: "warn", patched: "ok", accepted: "default" };

export function VulnInstances({ rows, canWrite }: { rows: Instance[]; canWrite: boolean }) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [note, setNote] = useState("");
  const { pending, error, run } = useAction();
  const open = rows.filter((r) => r.status === "open");
  const allChecked = open.length > 0 && open.every((r) => selected.has(r.id));

  const toggle = (id: string, on: boolean) =>
    setSelected((s) => {
      const n = new Set(s);
      if (on) n.add(id);
      else n.delete(id);
      return n;
    });

  const apply = (status: "patched" | "accepted" | "open") => {
    const ids = [...selected];
    run(
      () => markVulns(ids, status, note),
      () => {
        setSelected(new Set());
        setNote("");
      },
      {
        success: (n) => {
          const count = typeof n === "number" ? n : ids.length;
          return `${count} instance${count === 1 ? "" : "s"} ${status === "accepted" ? "marked risk accepted" : status === "open" ? "reopened" : "marked patched"}`;
        },
      },
    );
  };

  return (
    <div>
      {canWrite ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
          <span className="text-xs text-muted">{selected.size} selected</span>
          <Button size="sm" disabled={pending || !selected.size} onClick={() => apply("patched")}>Mark patched</Button>
          <Input className="h-7 w-72 text-xs" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Reason (required to accept risk)" aria-label="Reason for accepting risk" />
          <Button size="sm" variant="secondary" disabled={pending || !selected.size} onClick={() => apply("accepted")}>Accept risk</Button>
          <Button size="sm" variant="ghost" disabled={pending || !selected.size} onClick={() => apply("open")}>Reopen</Button>
          <ActionError error={error} />
        </div>
      ) : null}
      <Table>
        <THead>
          <tr className="border-b border-border">
            {canWrite ? (
              <TH className="w-8">
                <Checkbox
                  checked={allChecked}
                  onCheckedChange={(v) => setSelected(v === true ? new Set(open.map((r) => r.id)) : new Set())}
                  aria-label="Select all open instances"
                />
              </TH>
            ) : null}
            <TH>Priority</TH>
            <TH>Asset</TH>
            <TH>Package</TH>
            <TH>Installed</TH>
            <TH>Fixed in</TH>
            <TH>Status</TH>
          </tr>
        </THead>
        <TBody>
          {rows.map((r) => (
            <TR key={r.id}>
              {canWrite ? (
                <TD>
                  <Checkbox checked={selected.has(r.id)} onCheckedChange={(v) => toggle(r.id, v === true)} aria-label={`Select ${r.assetName} ${r.packageName ?? ""}`} />
                </TD>
              ) : null}
              <TD><RiskScore score={r.priorityScore} /></TD>
              <TD>
                <Link href={`/assets/${r.assetId}`} className="font-medium hover:text-accent">{r.assetName}</Link>
                <div className="text-[11px] text-muted">
                  criticality {r.criticality}/5{r.exposure === "internet" ? <span className="text-sev-critical"> · internet-facing</span> : ` · ${r.exposure}`}
                </div>
              </TD>
              <TD className="font-mono text-xs">{r.packageName ?? "—"}</TD>
              <TD className="font-mono text-xs">{r.packageVersion ?? "—"}</TD>
              <TD className="font-mono text-xs text-ok">{r.fixedVersion ?? "—"}</TD>
              <TD><Badge variant={STATUS_VARIANT[r.status] ?? "default"}>{r.status === "accepted" ? "risk accepted" : r.status}</Badge></TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}
