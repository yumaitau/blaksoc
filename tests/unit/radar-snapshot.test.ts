import { describe, expect, it } from "vitest";
import { collectRadar, outagesFrom, radarLabel, radarUrls, sharesFrom, unconfiguredRadar } from "@/lib/radar/snapshot";

const token = "a".repeat(40);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("radar parsing", () => {
  it("labels protocols and sorts the largest share first", () => {
    expect(radarLabel("udp")).toBe("UDP");
    expect(radarLabel("CABLE_CUT")).toBe("Cable Cut");
    expect(sharesFrom({
      success: true,
      result: { summary_0: { tcp: "10", udp: "70", other: "20" }, meta: {} },
    })).toEqual([
      { key: "udp", label: "UDP", pct: 70 },
      { key: "other", label: "Other", pct: 20 },
      { key: "tcp", label: "TCP", pct: 10 },
    ]);
  });

  it("reads an outage annotation", () => {
    expect(outagesFrom({
      success: true,
      result: {
        annotations: [{
          id: "out-1",
          startDate: "2026-10-09T00:00:00Z",
          endDate: null,
          scope: "Regional loss in Queensland",
          locations: ["AU"],
          locationsDetails: [{ code: "AU", name: "Australia" }],
          outage: { outageType: "REGIONAL", outageCause: "CABLE_CUT" },
        }],
      },
    })).toEqual([{
      id: "out-1",
      start: "2026-10-09T00:00:00Z",
      end: null,
      scope: "Regional loss in Queensland",
      cause: "Regional · Cable Cut",
      locations: "Australia",
    }]);
  });
});

describe("radar requests", () => {
  it("asks Radar for Australia and keeps the token out of the URL", async () => {
    const urls = radarUrls();
    expect(urls.l7).toContain("/radar/attacks/layer7/summary/industry");
    expect(urls.l3).toContain("/radar/attacks/layer3/summary/protocol");
    expect(urls.bots).toContain("/radar/http/summary/bot_class");
    expect(urls.outages).toContain("/radar/annotations/outages");
    for (const url of Object.values(urls)) {
      expect(url).toContain("location=AU");
      expect(url).not.toContain(token);
    }

    const seen: { url: string; authorization: string; redirect: RequestRedirect | undefined }[] = [];
    const snap = await collectRadar(token, async (url, init) => {
      const headers = new Headers(init.headers);
      seen.push({ url, authorization: headers.get("authorization") ?? "", redirect: init.redirect });
      if (url.includes("/annotations/outages")) return json({ success: true, result: { annotations: [] } });
      return json({ success: true, result: { summary_0: { waf: "80", ddos: "20" } } });
    });

    expect(seen).toHaveLength(4);
    expect(seen.every((call) => call.authorization === `Bearer ${token}` && call.redirect === "manual")).toBe(true);
    expect(snap.configured).toBe(true);
    expect(snap.l7.rows[0]).toMatchObject({ key: "waf", pct: 80 });
    expect(snap.l7.error).toBeNull();
    expect(snap.outages.rows).toEqual([]);
  });

  it("does not call Cloudflare without a token, and does not repeat a credential error", async () => {
    let calls = 0;
    const empty = await collectRadar("  ", async () => {
      calls += 1;
      return json({});
    });
    expect(empty).toEqual(unconfiguredRadar());
    expect(calls).toBe(0);

    const refused = await collectRadar(token, async () => json({ success: false, errors: [{ message: "Invalid API token abcsecret" }] }, 401));
    expect(refused.l7.error).toBe("Cloudflare Radar refused the API token. It needs Account > Radar > Read.");
    expect(refused.l7.error).not.toContain("abcsecret");
  });

  it("does not follow a redirect", async () => {
    const snap = await collectRadar(token, async () => new Response(null, { status: 302, headers: { location: "https://evil.example/steal" } }));
    expect(snap.l7.error).toMatch(/redirected/);
  });
});
