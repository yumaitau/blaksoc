import { describe, expect, it } from "vitest";
import {
  defaultWallboardLayout,
  movePanel,
  normalizeWallboardLayout,
  PANELS,
  placePanel,
  resizePanel,
  sameWallboardLayout,
  setPanelHidden,
  wallboardLayoutForSave,
} from "@/lib/wallboard/layout";
import { duration } from "@/components/wallboard/wallboard";

const ids = (layout: { id: string }[]) => layout.map((p) => p.id);

describe("wallboard layout", () => {
  it("falls back to the standard layout for garbage or an empty list", () => {
    for (const input of [null, "x", [], [{ id: "nope" }]]) expect(normalizeWallboardLayout(input)).toEqual(defaultWallboardLayout());
  });

  it("keeps the saved order and hides panels added after publishing", () => {
    const layout = normalizeWallboardLayout([{ id: "incidents", span: "full", hidden: false }, { id: "incidents" }, { id: "metrics", span: "wide" }]);
    expect(ids(layout).slice(0, 2)).toEqual(["incidents", "metrics"]);
    expect(layout[0]).toEqual({ id: "incidents", span: "full", hidden: false });
    expect(layout[1]).toEqual({ id: "metrics", span: "full", hidden: false });
    expect(layout).toHaveLength(PANELS.length);
    expect(layout.slice(2).every((p) => p.hidden)).toBe(true);
  });

  it("rejects malformed saves and a board with nothing visible", () => {
    expect(() => wallboardLayoutForSave([])).toThrow();
    expect(() => wallboardLayoutForSave([{ id: "metrics", span: "huge", hidden: false }])).toThrow("Unknown panel width.");
    expect(() => wallboardLayoutForSave([{ id: "unknown", span: "full", hidden: false }])).toThrow("Unknown wallboard panel.");
    expect(() => wallboardLayoutForSave([{ id: "metrics", span: "full", hidden: "no" }])).toThrow();
    expect(() => wallboardLayoutForSave(defaultWallboardLayout().map((p) => ({ ...p, hidden: true })))).toThrow("Show at least one panel on the wallboard.");
    expect(wallboardLayoutForSave(defaultWallboardLayout())).toEqual(defaultWallboardLayout());
  });

  it("drops a dragged panel at its target in either direction", () => {
    const base = defaultWallboardLayout();
    expect(ids(placePanel(base, "metrics", "incidents")).slice(0, 3)).toEqual(["customers", "incidents", "metrics"]);
    expect(ids(placePanel(base, "flow", "customers")).slice(0, 3)).toEqual(["metrics", "flow", "customers"]);
    expect(placePanel(base, "metrics", "metrics")).toBe(base);
  });

  it("moves between visible neighbours, resizes within bounds and hides", () => {
    const base = setPanelHidden(defaultWallboardLayout(), "customers", true);
    expect(ids(movePanel(base, "metrics", 1)).slice(0, 3)).toEqual(["incidents", "customers", "metrics"]);
    expect(movePanel(base, "metrics", -1)).toBe(base);
    expect(resizePanel(base, "metrics", 1).find((p) => p.id === "metrics")?.span).toBe("full");
    expect(resizePanel(base, "flow", 1).find((p) => p.id === "flow")?.span).toBe("half");
    expect(resizePanel(base, "flow", -1).find((p) => p.id === "flow")?.span).toBe("third");
    expect(sameWallboardLayout(base, defaultWallboardLayout())).toBe(false);
    expect(sameWallboardLayout(setPanelHidden(base, "customers", false), defaultWallboardLayout())).toBe(true);
  });

  it("formats durations for reading across a room", () => {
    expect(duration(-5)).toBe("0m");
    expect(duration(12 * 60_000)).toBe("12m");
    expect(duration(3 * 3600_000 + 10 * 60_000)).toBe("3h 10m");
    expect(duration(5 * 3600_000)).toBe("5h");
    expect(duration(50 * 3600_000)).toBe("2d 2h");
  });
});
