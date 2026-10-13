"use client";

import { ExternalLink } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { WallboardScreen, useNow, useRotation, type PanelEditor } from "@/components/wallboard/wallboard";
import {
  defaultWallboardLayout,
  isPanelId,
  movePanel,
  panelName,
  placePanel,
  resizePanel,
  sameWallboardLayout,
  setPanelHidden,
  type PanelId,
  type WallboardPanel,
} from "@/lib/wallboard/layout";
import type { WallboardSnapshot } from "@/lib/wallboard/types";
import { saveWallboardLayoutAction } from "./actions";

type Layouts = { published: WallboardPanel[]; draft: WallboardPanel[]; publishedAt: string | null };

const stamp = (value: string) => new Date(value).toLocaleString("en-AU", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

/** Arrange the office display on a live scale model, save a draft, preview it full screen, then publish. */
export function WallboardDesigner({ snapshot, initial }: { snapshot: WallboardSnapshot; initial: Layouts }) {
  const [saved, setSaved] = useState(initial);
  const [layout, setLayout] = useState(initial.draft);
  const [dragging, setDragging] = useState<PanelId | null>(null);
  const [over, setOver] = useState<PanelId | null>(null);
  const now = useNow();
  const page = useRotation();
  const { pending, error, run } = useAction();
  const model = useRef<HTMLDivElement>(null);
  const [overflows, setOverflows] = useState(false);

  // The scale model grows with its content; taller than 16:9 means the TV will need to scroll.
  useEffect(() => {
    const frame = model.current;
    const board = frame?.querySelector("main");
    if (!frame || !board) return;
    const check = () => setOverflows(board.scrollHeight > frame.clientWidth * 9 / 16 + 2);
    const observer = new ResizeObserver(check);
    observer.observe(board);
    check();
    return () => observer.disconnect();
  }, [layout]);

  const unsaved = !sameWallboardLayout(layout, saved.draft);
  const unpublished = !sameWallboardLayout(layout, saved.published);
  const hidden = layout.filter((p) => p.hidden);
  const noneVisible = hidden.length === layout.length;

  function persist(publish: boolean) {
    run(() => saveWallboardLayoutAction(layout, publish), (next) => {
      if (!next) return;
      setSaved(next);
      setLayout(next.draft);
    }, { success: publish ? "Wallboard published. Displays update on their next refresh." : "Draft saved." });
  }

  const editor: PanelEditor = {
    dragging,
    over,
    onDragStart: setDragging,
    onDragOver: (id) => setOver((current) => current === id ? current : id),
    onDrop: (id, source) => {
      const from = isPanelId(source) ? source : dragging;
      if (from) setLayout((current) => placePanel(current, from, id));
      setDragging(null);
      setOver(null);
    },
    onDragEnd: () => { setDragging(null); setOver(null); },
    onMove: (id, dir) => setLayout((current) => movePanel(current, id, dir)),
    onResize: (id, dir) => setLayout((current) => resizePanel(current, id, dir)),
    onHide: (id) => setLayout((current) => setPanelHidden(current, id, true)),
  };

  const state = unsaved ? "Unsaved changes" : unpublished ? "Draft saved · not yet published" : "Displays show this layout";

  return (
    <section className="space-y-4" aria-labelledby="designer-heading">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 id="designer-heading" className="text-lg font-semibold">Wallboard layout</h2>
          <p className="mt-1 max-w-3xl text-sm text-muted">Drag panels to reorder them. Hover or tab to a panel for move, width and hide controls. Save a draft and preview it full screen before publishing it to every display.</p>
          <p className="mt-2 text-xs text-muted" role="status"><span className={unsaved ? "text-warn" : unpublished ? "text-accent" : "text-ok"}>{state}</span>{saved.publishedAt ? ` · last published ${stamp(saved.publishedAt)}` : " · showing the standard layout"}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" variant="ghost" size="sm" disabled={pending} onClick={() => setLayout(defaultWallboardLayout())}>Standard layout</Button>
          <Button type="button" variant="ghost" size="sm" disabled={pending || !unpublished} onClick={() => setLayout(saved.published)}>Revert to published</Button>
          <Button type="button" variant="secondary" size="sm" disabled={pending || !unsaved || noneVisible} onClick={() => persist(false)}>Save draft</Button>
          {unsaved ? (
            <Button type="button" variant="secondary" size="sm" disabled title="Save the draft to preview it full screen"><ExternalLink aria-hidden="true" />Preview full screen</Button>
          ) : (
            <Button asChild variant="secondary" size="sm"><a href="/wallboard?preview=draft" target="_blank" rel="noopener noreferrer"><ExternalLink aria-hidden="true" />Preview full screen</a></Button>
          )}
          <Button type="button" size="sm" disabled={pending || !unpublished || noneVisible} onClick={() => persist(true)}>Publish</Button>
        </div>
      </div>
      <ActionError error={error} />

      <div className="rounded-lg border border-border bg-surface-2 p-3">
        <div className="mb-2 flex items-center justify-between text-[11px] uppercase tracking-wider text-faint"><span>Preview · 16:9 display · live data</span><span>{unsaved ? "Unsaved" : unpublished ? "Draft" : "Published"}</span></div>
        <div ref={model}><WallboardScreen data={{ ...snapshot, preview: unpublished }} now={now} page={page} layout={layout} editor={editor} embedded /></div>
        {overflows ? <p className="mt-2 text-xs text-warn" role="status">This arrangement is taller than one 16:9 screen, so the TV will scroll. Hide a panel or widen panels to fill rows.</p> : null}
      </div>

      <div className="rounded-lg border border-dashed border-border p-3">
        <div className="text-[11px] uppercase tracking-wider text-faint">Hidden panels</div>
        {hidden.length ? (
          <ul className="mt-2 flex flex-wrap gap-2">
            {hidden.map((p) => <li key={p.id}><Button type="button" variant="secondary" size="sm" onClick={() => setLayout((current) => setPanelHidden(current, p.id, false))}>Add {panelName(p.id)}</Button></li>)}
          </ul>
        ) : <p className="mt-1 text-sm text-muted">Every panel is on the wallboard.</p>}
        {noneVisible ? <p className="mt-2 text-sm text-warn">Add at least one panel before saving.</p> : null}
      </div>
    </section>
  );
}
