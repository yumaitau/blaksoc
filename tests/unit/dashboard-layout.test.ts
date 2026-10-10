import { describe, expect, it } from "vitest";
import {
  cycleSpan,
  defaultLayout,
  layoutForSave,
  moveWidget,
  normalizeLayout,
  placeWidget,
  setHidden,
  type DashboardWidget,
} from "@/lib/dashboard/layout";

describe("dashboard layout", () => {
  it("starts from the standard board, Radar included and visible", () => {
    const layout = defaultLayout();
    expect(layout.find((w) => w.id === "posture")).toMatchObject({ hidden: false, span: "full" });
    expect(layout.filter((w) => w.id.startsWith("radar-")).every((w) => !w.hidden)).toBe(true);
  });

  it("drops unknown ids, keeps the first duplicate, and hides widgets the saved row does not mention", () => {
    const saved = normalizeLayout([
      { id: "posture", span: "half", hidden: false },
      { id: "nope", span: "full", hidden: false },
      { id: "posture", span: "full", hidden: true },
      { id: "tools", span: "not-a-width", hidden: false },
    ]);
    expect(saved[0]).toEqual({ id: "posture", span: "half", hidden: false });
    expect(saved.filter((w) => w.id === "posture")).toHaveLength(1);
    expect(saved.find((w) => w.id === "tools")).toEqual({ id: "tools", span: "full", hidden: false });
    expect(saved.find((w) => w.id === "radar-l7")).toMatchObject({ hidden: true });
  });

  it("treats garbage as the standard board", () => {
    expect(normalizeLayout(null).map((w) => w.id)).toEqual(defaultLayout().map((w) => w.id));
    expect(normalizeLayout([])).toEqual(defaultLayout());
    expect(normalizeLayout([{ id: "nope" }])).toEqual(defaultLayout());
  });

  it("rejects a save with an unknown width and accepts a reordered board", () => {
    expect(() => layoutForSave([{ id: "posture", span: "huge", hidden: false }])).toThrow(/width/);
    expect(() => layoutForSave([])).toThrow(/not valid/);
    const saved = layoutForSave([{ id: "radar-outages", span: "full", hidden: false }]);
    expect(saved[0]).toEqual({ id: "radar-outages", span: "full", hidden: false });
    expect(saved.find((w) => w.id === "posture")?.hidden).toBe(true);
  });

  it("moves, resizes and hides without losing a widget", () => {
    const start = defaultLayout();
    const moved = moveWidget(start, "investigate", 1);
    const visible = (rows: DashboardWidget[]) => rows.filter((w) => !w.hidden).map((w) => w.id);
    const before = visible(start);
    const after = visible(moved);
    expect(after[before.indexOf("investigate")]).toBe("customers");
    expect(after[before.indexOf("customers")]).toBe("investigate");
    expect(moved).toHaveLength(start.length);

    const placed = placeWidget(start, "customers", "investigate");
    expect(placed.findIndex((w) => w.id === "customers")).toBeLessThan(placed.findIndex((w) => w.id === "investigate"));

    const wider = cycleSpan(start, "customers", 1);
    expect(wider.find((w) => w.id === "customers")?.span).toBe("half");
    const widest = cycleSpan(start, "tools", 1);
    expect(widest.find((w) => w.id === "tools")?.span).toBe("full");

    const hidden = setHidden(start, "fatigue", true);
    expect(hidden.find((w) => w.id === "fatigue")?.hidden).toBe(true);
    expect(moveWidget(hidden, "fatigue", 1)).toEqual(hidden);
  });
});
