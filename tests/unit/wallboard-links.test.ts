import { describe, expect, it } from "vitest";
import { displayLinkRows, type DisplayLink } from "@/lib/wallboard/display-links";

const link = (patch: Partial<DisplayLink> = {}): DisplayLink => ({ id: "office", name: "Office TV", tenantIds: ["customer-a"], createdBy: "manager", createdAt: "2026-10-09T00:00:00.000Z", expiresAt: "2026-10-10T00:00:00.000Z", revokedAt: null, ...patch });

describe("display link list revalidation", () => {
  it("reflects revocation and expiry updates from the server", () => {
    const fresh = link({ revokedAt: "2026-10-09T01:00:00.000Z", expiresAt: "2026-10-09T02:00:00.000Z" });
    expect(displayLinkRows([fresh], [link()], {})).toEqual([fresh]);
  });

  it("shows a just-created link until the refreshed server list includes it, without duplicating it", () => {
    expect(displayLinkRows([], [link()], {})).toEqual([link()]);
    expect(displayLinkRows([link()], [link()], {})).toEqual([link()]);
  });

  it("retains a successful local revocation while an older server response is still visible", () => {
    const revokedAt = "2026-10-09T01:00:00.000Z";
    expect(displayLinkRows([link()], [], { office: revokedAt })[0]?.revokedAt).toBe(revokedAt);
  });

  it("includes new server links and orders them by creation time", () => {
    const newer = link({ id: "meeting-room", createdAt: "2026-10-09T02:00:00.000Z" });
    expect(displayLinkRows([newer], [link()], {}).map((row) => row.id)).toEqual(["meeting-room", "office"]);
  });
});
