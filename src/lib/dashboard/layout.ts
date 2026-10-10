/** SOC dashboard widgets. Order and width are the analyst's; ids are not free text. */

export const SPANS = ["quarter", "side", "half", "wide", "full"] as const;
export type Span = (typeof SPANS)[number];

export const WIDGETS = [
  { id: "tools", title: "Companion tools", span: "full" },
  { id: "posture", title: "Posture", span: "full" },
  { id: "fatigue", title: "Alert fatigue", span: "full" },
  { id: "hermes", title: "Hermes this week", span: "full" },
  { id: "investigate", title: "Investigate next", span: "wide" },
  { id: "customers", title: "Customers at risk", span: "side" },
  { id: "incidents", title: "Active incidents", span: "wide" },
  { id: "containment", title: "Containment and response", span: "side" },
  { id: "intel", title: "Threat-intel matches", span: "quarter" },
  { id: "infra", title: "Top malicious infrastructure", span: "quarter" },
  { id: "attack", title: "ATT&CK activity", span: "quarter" },
  { id: "workload", title: "Analyst workload", span: "quarter" },
  { id: "vulns", title: "Vulnerable critical assets", span: "half" },
  { id: "advisories", title: "Emerging Australian threats", span: "half" },
  { id: "radar-l7", title: "Radar · application attacks", span: "half" },
  { id: "radar-l3", title: "Radar · network attacks", span: "half" },
  { id: "radar-outages", title: "Radar · internet outages", span: "half" },
  { id: "radar-bots", title: "Radar · bot traffic", span: "half" },
] as const satisfies readonly { id: string; title: string; span: Span }[];

export type WidgetId = (typeof WIDGETS)[number]["id"];

export type DashboardWidget = { id: WidgetId; span: Span; hidden: boolean };

const SPECS = new Map(WIDGETS.map((w) => [w.id, w] as const));

export function isWidgetId(id: string): id is WidgetId {
  return SPECS.has(id as WidgetId);
}

export function isSpan(span: string): span is Span {
  return (SPANS as readonly string[]).includes(span);
}

/** Twelve-column grid. Narrow screens stack. */
export const SPAN_CLASS: Record<Span, string> = {
  quarter: "col-span-12 sm:col-span-6 xl:col-span-3",
  side: "col-span-12 xl:col-span-4",
  half: "col-span-12 xl:col-span-6",
  wide: "col-span-12 xl:col-span-8",
  full: "col-span-12",
};

export function defaultLayout(): DashboardWidget[] {
  return WIDGETS.map((w) => ({ id: w.id, span: w.span, hidden: false }));
}

export function widgetTitle(id: WidgetId): string {
  return SPECS.get(id)?.title ?? id;
}

/**
 * Drop unknown ids and duplicates. Widgets added after a layout was saved stay hidden
 * so a new card does not appear on a board the analyst already arranged.
 * Garbage, or an empty list, is the default board (Radar included).
 */
export function normalizeLayout(input: unknown): DashboardWidget[] {
  if (!Array.isArray(input)) return defaultLayout();
  const seen = new Set<string>();
  const out: DashboardWidget[] = [];
  for (const item of input) {
    if (!item || typeof item !== "object") continue;
    const id = (item as { id?: unknown }).id;
    if (typeof id !== "string" || !isWidgetId(id) || seen.has(id)) continue;
    const spec = SPECS.get(id)!;
    const spanRaw = (item as { span?: unknown }).span;
    const span = typeof spanRaw === "string" && isSpan(spanRaw) ? spanRaw : spec.span;
    const hidden = (item as { hidden?: unknown }).hidden === true;
    seen.add(id);
    out.push({ id, span, hidden });
  }
  if (out.length === 0) return defaultLayout();
  for (const spec of WIDGETS) {
    if (!seen.has(spec.id)) out.push({ id: spec.id, span: spec.span, hidden: true });
  }
  return out;
}

/** Save path. Unknown ids are ignored; an unknown width is rejected; every catalog id ends up in the row. */
export function layoutForSave(input: unknown): DashboardWidget[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > 40) throw new Error("Dashboard layout is not valid.");
  for (const item of input) {
    if (!item || typeof item !== "object") throw new Error("Dashboard layout is not valid.");
    const row = item as { id?: unknown; span?: unknown; hidden?: unknown };
    if (typeof row.id !== "string" || !isWidgetId(row.id)) continue;
    if (typeof row.span !== "string" || !isSpan(row.span)) throw new Error("Unknown widget width.");
    if (typeof row.hidden !== "boolean") throw new Error("Dashboard layout is not valid.");
  }
  const layout = normalizeLayout(input);
  if (!layout.some((w) => inputHasId(input, w.id))) throw new Error("Choose at least one dashboard widget.");
  return layout;
}

function inputHasId(input: unknown[], id: string): boolean {
  return input.some((item) => !!item && typeof item === "object" && (item as { id?: unknown }).id === id);
}

/** Swap a visible widget with its visible neighbour. Hidden widgets keep their places. */
export function moveWidget(layout: DashboardWidget[], id: WidgetId, dir: -1 | 1): DashboardWidget[] {
  const visible = layout.filter((w) => !w.hidden);
  const i = visible.findIndex((w) => w.id === id);
  const other = visible[i + dir];
  if (i < 0 || !other) return layout;
  const a = layout.findIndex((w) => w.id === id);
  const b = layout.findIndex((w) => w.id === other.id);
  const next = layout.slice();
  const left = next[a];
  const right = next[b];
  if (!left || !right) return layout;
  next[a] = right;
  next[b] = left;
  return next;
}

/** Drop `from` immediately before `to` in the stored order. */
export function placeWidget(layout: DashboardWidget[], from: WidgetId, to: WidgetId): DashboardWidget[] {
  if (from === to) return layout;
  const moving = layout.find((w) => w.id === from);
  if (!moving) return layout;
  const next = layout.filter((w) => w.id !== from);
  const index = next.findIndex((w) => w.id === to);
  if (index < 0) return layout;
  next.splice(index, 0, moving);
  return next;
}

export function cycleSpan(layout: DashboardWidget[], id: WidgetId, dir: -1 | 1): DashboardWidget[] {
  return layout.map((w) => {
    if (w.id !== id) return w;
    const i = SPANS.indexOf(w.span);
    const n = i + dir;
    const span = SPANS[n];
    if (!span) return w;
    return { ...w, span };
  });
}

export function setHidden(layout: DashboardWidget[], id: WidgetId, hidden: boolean): DashboardWidget[] {
  return layout.map((w) => (w.id === id ? { ...w, hidden } : w));
}
