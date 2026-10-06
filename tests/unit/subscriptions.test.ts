import { describe, expect, it } from "vitest";
import { eventNotification, subscribesTo } from "@/lib/connectors/subscriptions";

describe("integration event subscriptions", () => {
  it("honours the events list on webhook, Teams and Slack configs", () => {
    expect(subscribesTo({ events: ["incident.created", "approval.requested"] }, "incident.created")).toBe(true);
    expect(subscribesTo({ events: ["incident.created"] }, "alert.created")).toBe(false);
    expect(subscribesTo({ from: "+61400000000" }, "incident.created")).toBe(false);
    expect(subscribesTo(null, "incident.created")).toBe(false);
  });

  it("builds a notification with a deep link and no raw telemetry", () => {
    const n = eventNotification({ type: "incident.created", tenantId: "t1", id: "i1", title: "Ransomware on FS01", severity: "critical" }, "Wattle Health", "https://soc.example.com.au");
    expect(n).toMatchObject({ event: "incident.created", title: "Ransomware on FS01", severity: "critical", url: "https://soc.example.com.au/soc/incidents/i1", tenant: { id: "t1", name: "Wattle Health" } });
    const a = eventNotification({ type: "approval.requested", tenantId: "t1", id: "a1", summary: "Isolate endpoint FS01" }, "Wattle Health", "https://soc.example.com.au");
    expect(a.url).toBe("https://soc.example.com.au/soc/approvals");
    expect(a.title).toContain("Isolate endpoint FS01");
  });
});
