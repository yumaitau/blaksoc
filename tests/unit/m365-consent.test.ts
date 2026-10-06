process.env.M365_CONNECTOR_CLIENT_ID = "connector-app";
process.env.M365_CONNECTOR_CLIENT_SECRET = "connector-secret";

import { describe, expect, it } from "vitest";
import { adminConsentUrl, ConsentError, consentConfigured, parseCallback, signState, verifyConsent, verifyState } from "@/lib/onboarding/m365-consent";
import type { GraphTransport } from "@/lib/providers/m365/graph";

const TENANT = "0b6e4f00-1111-4222-8333-944445555666";
const noSleep = async () => {};

function transport(routes: Record<string, { status: number; body: unknown }[]>): GraphTransport & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async request(method, path) {
      calls.push(`${method} ${path}`);
      const queue = routes[path] ?? [];
      const next = queue.length > 1 ? queue.shift()! : queue[0] ?? { status: 404, body: {} };
      return { status: next.status, headers: {}, body: next.body };
    },
  };
}

describe("Microsoft 365 admin consent", () => {
  it("builds the admin consent URL for the connector app", () => {
    expect(consentConfigured()).toBe(true);
    const url = new URL(adminConsentUrl("s"));
    expect(url.pathname).toBe("/organizations/v2.0/adminconsent");
    expect(url.searchParams.get("client_id")).toBe("connector-app");
    expect(url.searchParams.get("scope")).toBe("https://graph.microsoft.com/.default");
    expect(url.searchParams.get("redirect_uri")).toMatch(/\/onboarding\/m365\/callback$/);
  });

  it("binds state to the analyst and a short window", () => {
    const now = Date.now();
    const state = signState("draft-1", "user-1", now);
    expect(verifyState(state, "user-1", now).draftId).toBe("draft-1");
    expect(() => verifyState(state, "user-2", now)).toThrow(ConsentError);
    expect(() => verifyState(state, "user-1", now + 31 * 60_000)).toThrow(/expired/);
    const [payload, sig] = state.split(".");
    const forged = Buffer.from(JSON.stringify({ draftId: "other", userId: "user-1", exp: now + 60_000, nonce: "x" })).toString("base64url");
    expect(() => verifyState(`${forged}.${sig}`, "user-1", now)).toThrow(/signature/);
    expect(() => verifyState(payload!, "user-1", now)).toThrow(/malformed/);
  });

  it("reads the redirect and refuses a declined or malformed one", () => {
    expect(parseCallback(new URLSearchParams({ tenant: TENANT.toUpperCase(), admin_consent: "True", state: "s" }))).toEqual({ azureTenantId: TENANT, state: "s" });
    expect(() => parseCallback(new URLSearchParams({ error: "access_denied", error_description: "declined", state: "s" }))).toThrow(/access_denied/);
    expect(() => parseCallback(new URLSearchParams({ tenant: TENANT, admin_consent: "False" }))).toThrow(/not granted/);
    expect(() => parseCallback(new URLSearchParams({ tenant: "contoso", admin_consent: "True" }))).toThrow(/tenant id/);
  });

  it("proves consent with a Graph read of the organisation and licences", async () => {
    const t = transport({
      "/organization": [{ status: 200, body: { value: [{ id: TENANT, displayName: "River Clinic" }] } }],
      "/subscribedSkus": [{ status: 200, body: { value: [{ skuPartNumber: "O365_BUSINESS_PREMIUM" }, { skuPartNumber: "AAD_PREMIUM" }] } }],
    });
    const consent = await verifyConsent(TENANT, { transport: t, sleep: noSleep, now: new Date("2026-10-06T00:00:00Z") });
    expect(consent).toEqual({ azureTenantId: TENANT, organisation: "River Clinic", grantedAt: "2026-10-06T00:00:00.000Z", skus: ["O365_BUSINESS_PREMIUM", "AAD_PREMIUM"] });
  });

  it("retries while new consent propagates, and refuses another tenant's organisation", async () => {
    const slow = transport({
      "/organization": [{ status: 403, body: {} }, { status: 200, body: { value: [{ id: TENANT, displayName: "River" }] } }],
      "/subscribedSkus": [{ status: 200, body: { value: [] } }],
    });
    expect((await verifyConsent(TENANT, { transport: slow, sleep: noSleep })).organisation).toBe("River");
    expect(slow.calls.filter((c) => c === "GET /organization").length).toBe(2);

    const wrong = transport({ "/organization": [{ status: 200, body: { value: [{ id: "ffffffff-1111-4222-8333-944445555666" }] } }] });
    await expect(verifyConsent(TENANT, { transport: wrong, sleep: noSleep })).rejects.toThrow(/does not match/);

    const never = transport({ "/organization": [{ status: 403, body: {} }] });
    await expect(verifyConsent(TENANT, { transport: never, sleep: noSleep, attempts: 2 })).rejects.toThrow(/403/);
  });
});
