"use client";

import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { PageHeader } from "@/components/soc/indicators";
import { Button } from "@/components/ui/button";
import { saveDashboardLayout } from "@/app/(app)/soc/dashboard-actions";
import {
  cycleSpan,
  defaultLayout,
  moveWidget,
  placeWidget,
  setHidden,
  SPAN_CLASS,
  widgetTitle,
  type DashboardWidget,
  type WidgetId,
} from "@/lib/dashboard/layout";

export function DashboardBoard({
  scope,
  initial,
  slots,
}: {
  scope: string;
  initial: DashboardWidget[];
  slots: Partial<Record<WidgetId, ReactNode>>;
}) {
  const [editing, setEditing] = useState(false);
  const [layout, setLayout] = useState(initial);
  const [baseline, setBaseline] = useState(initial);
  const dragId = useRef<WidgetId | null>(null);
  const { pending, error, setError, run } = useAction();

  const visible = layout.filter((w) => !w.hidden && slots[w.id] != null);
  const hidden = layout.filter((w) => w.hidden && slots[w.id] != null);

  function save(next: DashboardWidget[], done: string) {
    run(() => saveDashboardLayout(next), () => {
      setBaseline(next);
      setLayout(next);
      setEditing(false);
    }, { success: done });
  }

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Operate"
        title="SOC dashboard"
        description={editing
          ? "Reorder, resize and hide widgets. Save keeps this arrangement for you."
          : `Live posture across ${scope}. Everything here links to the work it needs.`}
        actions={editing ? (
          <>
            <Button type="button" variant="ghost" size="sm" disabled={pending} onClick={() => { setLayout(defaultLayout()); setError(null); }}>Reset</Button>
            <Button type="button" variant="secondary" size="sm" disabled={pending} onClick={() => { setLayout(baseline); setEditing(false); setError(null); }}>Cancel</Button>
            <Button type="button" size="sm" disabled={pending} onClick={() => save(layout, "Dashboard saved.")}>Save</Button>
          </>
        ) : (
          <Button type="button" variant="secondary" size="sm" onClick={() => { setLayout(baseline); setEditing(true); setError(null); }}>Customise</Button>
        )}
      />
      <ActionError error={error} />

      <div className="grid grid-cols-12 gap-5">
        {visible.map((w) => (
          <div
            key={w.id}
            className={`${SPAN_CLASS[w.span]} min-w-0 ${editing ? "rounded-lg ring-1 ring-accent/40" : ""}`}
            onDragOver={editing ? (e) => e.preventDefault() : undefined}
            onDrop={editing ? (e) => {
              e.preventDefault();
              const from = dragId.current;
              dragId.current = null;
              if (!from) return;
              setLayout((current) => placeWidget(current, from, w.id));
            } : undefined}
          >
            {editing ? (
              <div className="mb-2 flex flex-wrap items-center gap-1 px-1">
                <button
                  type="button"
                  draggable
                  className="cursor-grab px-1 text-xs text-muted"
                  aria-label={`Drag ${widgetTitle(w.id)}`}
                  onDragStart={() => { dragId.current = w.id; }}
                  onDragEnd={() => { dragId.current = null; }}
                >
                  Drag
                </button>
                <span className="mr-auto truncate text-xs font-medium">{widgetTitle(w.id)}</span>
                <Button type="button" variant="ghost" size="sm" onClick={() => setLayout((current) => moveWidget(current, w.id, -1))}>Up</Button>
                <Button type="button" variant="ghost" size="sm" onClick={() => setLayout((current) => moveWidget(current, w.id, 1))}>Down</Button>
                <Button type="button" variant="ghost" size="sm" onClick={() => setLayout((current) => cycleSpan(current, w.id, -1))}>Narrower</Button>
                <Button type="button" variant="ghost" size="sm" onClick={() => setLayout((current) => cycleSpan(current, w.id, 1))}>Wider</Button>
                <Button type="button" variant="ghost" size="sm" onClick={() => setLayout((current) => setHidden(current, w.id, true))}>Hide</Button>
              </div>
            ) : null}
            {slots[w.id]}
          </div>
        ))}
      </div>

      {editing ? (
        <div className="rounded-lg border border-dashed border-border p-3">
          <div className="text-[11px] uppercase tracking-wider text-faint">Hidden</div>
          {hidden.length === 0 ? <p className="mt-1 text-sm text-muted">Every available widget is on the board.</p> : (
            <ul className="mt-2 flex flex-wrap gap-2">
              {hidden.map((w) => (
                <li key={w.id}>
                  <Button type="button" variant="secondary" size="sm" onClick={() => setLayout((current) => setHidden(current, w.id, false))}>
                    Add {widgetTitle(w.id)}
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-2 text-[11px] text-muted">Reset restores the standard board, including Cloudflare Radar. Save to keep it.</p>
        </div>
      ) : null}
    </div>
  );
}
