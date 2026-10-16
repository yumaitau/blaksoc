import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { WallboardScreen } from "@/components/wallboard/wallboard";
import { unconfiguredRadar } from "@/lib/radar/snapshot";
import { defaultWallboardLayout, type WallboardPanel } from "@/lib/wallboard/layout";
import type { WallboardCustomer, WallboardSnapshot } from "@/lib/wallboard/types";

const customersOnly: WallboardPanel[] = [{ id: "customers", span: "twoThirds", hidden: false }];

function render(customers: WallboardCustomer[]) {
  const data: WallboardSnapshot = {
    generatedAt: "2026-10-16T00:00:00.000Z", scopeName: "All customers", customerCount: customers.length,
    counts: { openAlerts: 0, criticalAlerts: 0, awaitingTriage: 0, unassigned: 0, activeIncidents: 0, overdueIncidents: 0, pendingApprovals: 0, newLastHour: 0, closedLast24h: 0, intelMatched: 0, incidentsOpened24h: 0, incidentsClosed24h: 0 },
    activity: [], severity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }, oldestUntriagedAt: null, techniques: [],
    customers, incidentSummary: [], radar: unconfiguredRadar(), linkExpiresAt: null, layout: defaultWallboardLayout(), preview: false,
  };
  return renderToStaticMarkup(createElement(WallboardScreen, { data, now: Date.parse(data.generatedAt), page: 0, layout: customersOnly }));
}

const customer = (name: string, noncompliantEndpoints: number): WallboardCustomer => ({
  id: name, name, openAlerts: 0, criticalAlerts: 0, awaitingTriage: 0, activeIncidents: 0, offlineEndpoints: 0, noncompliantEndpoints, endpoints: 9, healthAlerts: 0, risk: 0,
});

describe("wallboard customer posture", () => {
  it("shows each customer's non-compliant devices, highlighted only when there are any", () => {
    const html = render([customer("Wattle", 3), customer("Murray", 0)]);
    expect(html).toContain(">Non-compliant</th>");
    const cells = [...html.matchAll(/<tr><th scope="row">.*?<\/tr>/g)].map((m) => m[0].match(/<td[^>]*>[^<]*<\/td><\/tr>$/)![0]);
    expect(cells[0]).toMatch(/class="[^"]*warning[^"]*">3</);
    expect(cells[1]).not.toMatch(/warning/);
    expect(cells[1]).toContain(">0<");
  });
});
