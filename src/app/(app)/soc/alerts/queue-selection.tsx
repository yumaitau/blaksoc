"use client";
import { ChevronDown, FilePlus2, FolderInput, UserCheck, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { createContext, use, useMemo, useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Label, Select } from "@/components/ui/input";
import { addSelectionToIncident, assignAlertsToMe, createIncidentFromSelection, setAlertStatus } from "./actions";

type Row = { id: string; tenantId: string };
type OpenIncident = { id: string; ref: number; title: string; tenantId: string; tenantName: string };

type Selection = {
  rows: Row[];
  selected: Map<string, string>;
  toggle: (row: Row, on: boolean) => void;
  setAll: (on: boolean) => void;
  clear: () => void;
};

const plural = (n: number) => `${n} alert${n === 1 ? "" : "s"}`;

const SelectionContext = createContext<Selection | null>(null);

function useSelection() {
  const s = use(SelectionContext);
  if (!s) throw new Error("useSelection outside QueueSelection");
  return s;
}

/** Holds row selection for the server-rendered queue table; rows stay server components. */
export function QueueSelection({ rows, children }: { rows: Row[]; children: React.ReactNode }) {
  const [selected, setSelected] = useState(() => new Map<string, string>());
  const value = useMemo<Selection>(
    () => ({
      rows,
      selected,
      toggle: (row, on) =>
        setSelected((prev) => {
          const next = new Map(prev);
          if (on) next.set(row.id, row.tenantId);
          else next.delete(row.id);
          return next;
        }),
      setAll: (on) => setSelected(on ? new Map(rows.map((r) => [r.id, r.tenantId])) : new Map()),
      clear: () => setSelected(new Map()),
    }),
    [rows, selected],
  );
  return <SelectionContext value={value}>{children}</SelectionContext>;
}

export function SelectAllCheckbox() {
  const { rows, selected, setAll } = useSelection();
  const state = selected.size === 0 ? false : selected.size === rows.length ? true : "indeterminate";
  return <Checkbox aria-label="Select all alerts on this page" checked={state} onCheckedChange={(v) => setAll(v === true)} disabled={!rows.length} />;
}

export function RowCheckbox({ id, tenantId, title }: Row & { title: string }) {
  const { selected, toggle } = useSelection();
  return <Checkbox aria-label={`Select alert ${title}`} checked={selected.has(id)} onCheckedChange={(v) => toggle({ id, tenantId }, v === true)} />;
}

export function BulkBar({ statuses, openIncidents, canTriage }: { statuses: readonly string[]; openIncidents: OpenIncident[]; canTriage: boolean }) {
  const { selected, clear } = useSelection();
  const router = useRouter();
  const { pending, error, run } = useAction();
  const [addOpen, setAddOpen] = useState(false);
  const ids = [...selected.keys()];
  const tenantIds = [...new Set(selected.values())];

  if (!canTriage || ids.length === 0) return null;

  return (
    <div className="sticky top-0 z-10 flex flex-wrap items-center gap-2 border-b border-border bg-surface-2 px-3 py-2" role="region" aria-label="Bulk actions">
      <span className="num text-sm font-medium">{ids.length} selected</span>
      <Button size="sm" variant="secondary" disabled={pending} onClick={() => run(() => assignAlertsToMe(ids), clear, { success: (n) => `${plural(n ?? ids.length)} assigned to you` })}>
        <UserCheck /> Assign to me
      </Button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="sm" variant="secondary" disabled={pending}>Set status <ChevronDown /></Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuLabel>Set status</DropdownMenuLabel>
          {statuses.map((s) => (
            <DropdownMenuItem key={s} onSelect={() => run(() => setAlertStatus(ids, s), clear, { success: (n) => `${plural(n ?? ids.length)} marked ${s.replaceAll("_", " ")}` })}>{s.replaceAll("_", " ")}</DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
      <Button size="sm" variant="secondary" disabled={pending} onClick={() => run(() => createIncidentFromSelection(ids, tenantIds), (d) => d && router.push(`/soc/incidents/${d.id}`), { success: `Incident created from ${plural(ids.length)}` })}>
        <FilePlus2 /> Create incident
      </Button>
      <Button size="sm" variant="secondary" disabled={pending} onClick={() => setAddOpen(true)}>
        <FolderInput /> Add to incident
      </Button>
      <Button size="sm" variant="ghost" onClick={clear} aria-label="Clear selection">
        <X /> Clear
      </Button>
      <div className="basis-full empty:hidden"><ActionError error={error} /></div>
      <AddToIncidentDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        incidents={openIncidents.filter((i) => tenantIds.length === 1 && i.tenantId === tenantIds[0])}
        mixedTenants={tenantIds.length > 1}
        onPick={(incidentId) => run(() => addSelectionToIncident(incidentId, ids), (d) => { setAddOpen(false); clear(); if (d) router.push(`/soc/incidents/${d.id}`); }, { success: `${plural(ids.length)} added to the incident` })}
        pending={pending}
        error={error}
      />
    </div>
  );
}

function AddToIncidentDialog({ open, onOpenChange, incidents, mixedTenants, onPick, pending, error }: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  incidents: OpenIncident[];
  mixedTenants: boolean;
  onPick: (id: string) => void;
  pending: boolean;
  error: string | null;
}) {
  const [choice, setChoice] = useState("");
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Add alerts to an incident" description="Only open incidents for the same customer as the selected alerts are listed.">
        {mixedTenants ? (
          <p className="text-sm text-warn">The selection spans more than one customer. Select alerts from a single customer first.</p>
        ) : incidents.length === 0 ? (
          <p className="text-sm text-muted">This customer has no open incidents. Use &ldquo;Create incident&rdquo; instead.</p>
        ) : (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (choice) onPick(choice);
            }}
          >
            <div>
              <Label htmlFor="add-incident">Incident</Label>
              <Select id="add-incident" required value={choice} onChange={(e) => setChoice(e.target.value)}>
                <option value="">Choose an incident…</option>
                {incidents.map((i) => (
                  <option key={i.id} value={i.id}>INC-{i.ref} · {i.title}</option>
                ))}
              </Select>
            </div>
            <ActionError error={error} />
            <div className="flex justify-end">
              <Button type="submit" disabled={pending || !choice}>Add alerts</Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
