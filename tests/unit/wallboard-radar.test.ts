import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { WallboardScreen } from "@/components/wallboard/wallboard";
import { unconfiguredRadar, type RadarSnapshot } from "@/lib/radar/snapshot";
import { defaultWallboardLayout, type WallboardPanel } from "@/lib/wallboard/layout";
import type { WallboardSnapshot } from "@/lib/wallboard/types";

const RADAR = ["radar-l7", "radar-l3", "radar-outages", "radar-bots"] as const;

function snapshot(radar: RadarSnapshot): WallboardSnapshot {
  return {
    generatedAt: "2026-10-15T00:00:00.000Z", scopeName: "All customers", customerCount: 1,
    counts: { openAlerts: 0, criticalAlerts: 0, awaitingTriage: 0, unassigned: 0, activeIncidents: 0, overdueIncidents: 0, pendingApprovals: 0, newLastHour: 0, closedLast24h: 0, intelMatched: 0, incidentsOpened24h: 0, incidentsClosed24h: 0 },
    activity: [], severity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }, oldestUntriagedAt: null, techniques: [],
    customers: [], incidentSummary: [], radar, linkExpiresAt: null, layout: defaultWallboardLayout(), preview: false,
  };
}

const radarOnly: WallboardPanel[] = RADAR.map((id) => ({ id, span: "third", hidden: false }));
const render = (data: WallboardSnapshot) => renderToStaticMarkup(createElement(WallboardScreen, { data, now: Date.parse(data.generatedAt), page: 0, layout: radarOnly }));

describe("wallboard Radar panels", () => {
  it("ship hidden so a published board only gains them through the designer", () => {
    const layout = defaultWallboardLayout();
    for (const id of RADAR) expect(layout.find((p) => p.id === id)).toMatchObject({ hidden: true });
  });

  it("explain the missing token instead of showing figures", () => {
    const html = render(snapshot(unconfiguredRadar()));
    expect(html.match(/CLOUDFLARE_RADAR_TOKEN/g)).toHaveLength(4);
  });

  it("show shares, outages and per-section errors", () => {
    const html = render(snapshot({
      configured: true,
      l7: { rows: [{ key: "finance", label: "Finance", pct: 41.25 }], error: null },
      l3: { rows: [], error: "Cloudflare Radar returned 500." },
      bots: { rows: [], error: null },
      outages: { rows: [{ id: "o1", start: "2026-10-14T01:00:00Z", end: null, scope: "Telstra", cause: "Power Outage", locations: "Australia" }], error: null },
    }));
    expect(html).toContain("Finance");
    expect(html).toContain("41.3%");
    expect(html).toContain("Cloudflare Radar returned 500.");
    expect(html).toContain("No Radar data in this window.");
    expect(html).toContain("Telstra");
    expect(html).toContain("Ongoing since");
    expect(html).not.toContain("CLOUDFLARE_RADAR_TOKEN");
  });
});
