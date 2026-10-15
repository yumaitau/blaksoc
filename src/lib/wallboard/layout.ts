/** Office wallboard panels. One published arrangement drives every display; managers edit a draft first. */

export const PANEL_SPANS = ["third", "half", "twoThirds", "full"] as const;
export type PanelSpan = (typeof PANEL_SPANS)[number];

export const PANELS = [
  { id: "metrics", name: "Headline numbers", span: "full", hidden: false },
  { id: "customers", name: "Customer posture", span: "twoThirds", hidden: false },
  { id: "incidents", name: "Priority incidents", span: "third", hidden: false },
  { id: "activity", name: "Alert activity", span: "third", hidden: false },
  { id: "severity", name: "Open alerts by severity", span: "third", hidden: false },
  { id: "flow", name: "Queue flow", span: "third", hidden: false },
  { id: "techniques", name: "ATT&CK techniques", span: "third", hidden: true },
  { id: "radar-l7", name: "Radar application attacks", span: "third", hidden: true },
  { id: "radar-l3", name: "Radar network attacks", span: "third", hidden: true },
  { id: "radar-outages", name: "Radar internet outages", span: "third", hidden: true },
  { id: "radar-bots", name: "Radar bot traffic", span: "third", hidden: true },
] as const satisfies readonly { id: string; name: string; span: PanelSpan; hidden: boolean }[];

export type PanelId = (typeof PANELS)[number]["id"];
export type WallboardPanel = { id: PanelId; span: PanelSpan; hidden: boolean };

const SPECS = new Map(PANELS.map((p) => [p.id, p] as const));

export function isPanelId(id: string): id is PanelId {
  return SPECS.has(id as PanelId);
}

export function isPanelSpan(span: string): span is PanelSpan {
  return (PANEL_SPANS as readonly string[]).includes(span);
}

export function panelName(id: PanelId): string {
  return SPECS.get(id)?.name ?? id;
}

export function defaultWallboardLayout(): WallboardPanel[] {
  return PANELS.map((p) => ({ id: p.id, span: p.span, hidden: p.hidden }));
}

/**
 * Drop unknown ids and duplicates. Panels added after a layout was published stay hidden
 * so a new panel never appears on a TV nobody previewed. Garbage or an empty list is the default.
 */
export function normalizeWallboardLayout(input: unknown): WallboardPanel[] {
  if (!Array.isArray(input)) return defaultWallboardLayout();
  const seen = new Set<string>();
  const out: WallboardPanel[] = [];
  for (const item of input) {
    if (!item || typeof item !== "object") continue;
    const { id, span, hidden } = item as { id?: unknown; span?: unknown; hidden?: unknown };
    if (typeof id !== "string" || !isPanelId(id) || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, span: typeof span === "string" && isPanelSpan(span) ? span : SPECS.get(id)!.span, hidden: hidden === true });
  }
  if (!out.length) return defaultWallboardLayout();
  for (const spec of PANELS) if (!seen.has(spec.id)) out.push({ id: spec.id, span: spec.span, hidden: true });
  return out;
}

/** Save path. Rejects malformed rows instead of guessing, and requires at least one visible panel. */
export function wallboardLayoutForSave(input: unknown): WallboardPanel[] {
  if (!Array.isArray(input) || !input.length || input.length > 20) throw new Error("Wallboard layout is not valid.");
  for (const item of input) {
    if (!item || typeof item !== "object") throw new Error("Wallboard layout is not valid.");
    const row = item as { id?: unknown; span?: unknown; hidden?: unknown };
    if (typeof row.id !== "string" || !isPanelId(row.id)) throw new Error("Unknown wallboard panel.");
    if (typeof row.span !== "string" || !isPanelSpan(row.span)) throw new Error("Unknown panel width.");
    if (typeof row.hidden !== "boolean") throw new Error("Wallboard layout is not valid.");
  }
  const layout = normalizeWallboardLayout(input);
  if (!layout.some((p) => !p.hidden)) throw new Error("Show at least one panel on the wallboard.");
  return layout;
}

export function sameWallboardLayout(a: readonly WallboardPanel[], b: readonly WallboardPanel[]): boolean {
  return a.length === b.length && a.every((p, i) => p.id === b[i]?.id && p.span === b[i]?.span && p.hidden === b[i]?.hidden);
}

/** Swap a visible panel with its visible neighbour. Hidden panels keep their places. */
export function movePanel(layout: WallboardPanel[], id: PanelId, dir: -1 | 1): WallboardPanel[] {
  const visible = layout.filter((p) => !p.hidden);
  const other = visible[visible.findIndex((p) => p.id === id) + dir];
  if (!other || other.id === id) return layout;
  const a = layout.findIndex((p) => p.id === id);
  const b = layout.findIndex((p) => p.id === other.id);
  if (a < 0) return layout;
  const next = layout.slice();
  [next[a], next[b]] = [next[b]!, next[a]!];
  return next;
}

/** Drop `from` where `to` is: before it when moving up, after it when moving down. */
export function placePanel(layout: WallboardPanel[], from: PanelId, to: PanelId): WallboardPanel[] {
  const a = layout.findIndex((p) => p.id === from);
  const b = layout.findIndex((p) => p.id === to);
  if (from === to || a < 0 || b < 0) return layout;
  const next = layout.slice();
  const [moving] = next.splice(a, 1);
  next.splice(b, 0, moving!);
  return next;
}

export function resizePanel(layout: WallboardPanel[], id: PanelId, dir: -1 | 1): WallboardPanel[] {
  return layout.map((p) => {
    const span = p.id === id ? PANEL_SPANS[PANEL_SPANS.indexOf(p.span) + dir] : undefined;
    return span ? { ...p, span } : p;
  });
}

export function setPanelHidden(layout: WallboardPanel[], id: PanelId, hidden: boolean): WallboardPanel[] {
  return layout.map((p) => (p.id === id ? { ...p, hidden } : p));
}
