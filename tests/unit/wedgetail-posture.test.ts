import { afterEach, describe, expect, it } from "vitest";
import { setEgressTransport } from "@/lib/net/egress";
import { fetchPosture, mcpClient, mcpEndpoint, parseE8, parseIsm, parseMitre, WEDGETAIL_TOKEN, WedgetailApiError } from "@/lib/wedgetail/posture";
import { E8, ISM, MITRE, TOKEN } from "../fixtures/wedgetail-posture";

afterEach(() => setEgressTransport());

describe("Wedgetail posture", () => {
  it("keeps aggregate ISM fields only and counts statuses", () => {
    const ism = parseIsm(ISM);
    expect(ism.counts).toEqual({ met: 1, partial: 1, not_met: 1, not_applicable: 0 });
    expect(ism.controls[0]).toEqual({ id: "ISM-1509", title: "Privileged access events are logged", topic: "privileged", responsibility: "wedgetail", status: "met", reason: "Root rule active", e8: [2, 3], withdrawn: false, detections: { mapped: 4, active: 4 } });
    expect(ism.controls[2]?.withdrawn).toBe(true);
    expect(JSON.stringify(ism)).not.toMatch(/owner|CISO|review|verified/);
    expect(() => parseIsm({ ...ISM, controls: [{ ...ISM.controls[0], id: "1509; drop" }] })).toThrow();
  });

  it("dedupes techniques across tactics, keeps ATLAS and ignores disabled-only techniques", () => {
    const mitre = parseMitre(MITRE)!;
    expect(mitre.techniques).toEqual([{ id: "AML.T0051.001", rules: 1, hunting: 0 }, { id: "T1078", rules: 2, hunting: 1 }]);
    expect(mitre.gaps).toEqual(["T1190"]);
    expect(mitre.totals.relevantCovered).toBe(2);
    expect(parseMitre({ available: false, note: "No sources" })).toBeNull();
  });

  it("accepts only HTTPS console origins and wtp_ tokens", () => {
    expect(mcpEndpoint("https://wedgetail.example.com/app/home?x=1").toString()).toBe("https://wedgetail.example.com/mcp");
    expect(() => mcpEndpoint("http://wedgetail.example.com")).toThrow(WedgetailApiError);
    expect(() => mcpEndpoint("https://user:pass@wedgetail.example.com")).toThrow(WedgetailApiError);
    expect(WEDGETAIL_TOKEN.test(TOKEN)).toBe(true);
    expect(() => mcpClient("https://wedgetail.example.com", "Bearer abc")).toThrow(/wtp_/);
  });

  it("calls tools/call with a bearer token, no Origin, and reads structuredContent", async () => {
    const seen: { url: string; headers: Record<string, string>; body: { method: string; params: { name: string } } }[] = [];
    setEgressTransport(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      seen.push({ url: String(input), headers: init?.headers as Record<string, string>, body });
      const structured = body.params.name === "ism_status" ? ISM : body.params.name === "essential_eight_summary" ? E8 : MITRE;
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { isError: false, content: [{ type: "text", text: "…" }], structuredContent: structured } }), { status: 200 });
    });
    const posture = await fetchPosture(mcpClient("https://wedgetail.example.com", TOKEN));
    expect(posture.ism.release).toBe("September 2026");
    expect(posture.mitre?.techniques).toHaveLength(2);
    expect(posture.e8?.strategies.map((s) => s.strategy)).toEqual(["mfa", "restrict_admin"]);
    expect(seen.map((s) => s.body.params.name)).toEqual(["ism_status", "mitre_coverage", "essential_eight_summary"]);
    expect(seen[0]).toMatchObject({ url: "https://wedgetail.example.com/mcp", headers: { authorization: `Bearer ${TOKEN}` }, body: { method: "tools/call" } });
    expect(Object.keys(seen[0]!.headers).map((h) => h.toLowerCase())).not.toContain("origin");
  });

  it("maps Wedgetail strategies to blakSOC's, drops unknown ones and keeps no requirement list", () => {
    const e8 = parseE8(E8);
    expect(e8.strategies).toEqual([
      { strategy: "mfa", maturity: 1, levels: E8.strategies[0]!.levels },
      { strategy: "restrict_admin", maturity: 0, levels: E8.strategies[1]!.levels },
    ]);
    expect(JSON.stringify(e8)).not.toContain("requirements");
  });

  it("pulls ISM and ATT&CK without the Essential Eight summary when the install lacks the tool or refuses it", async () => {
    for (const refusal of [
      { error: { code: -32602, message: "Unknown tool: essential_eight_summary" } },
      { result: { isError: true, content: [{ type: "text", text: "{\"error\":\"Not available to scoped users\"}" }] } },
    ]) {
      setEgressTransport(async (_input, init) => {
        const body = JSON.parse(String(init?.body));
        if (body.params.name === "essential_eight_summary") return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, ...refusal }), { status: 200 });
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { isError: false, content: [], structuredContent: body.params.name === "ism_status" ? ISM : MITRE } }), { status: 200 });
      });
      const posture = await fetchPosture(mcpClient("https://wedgetail.example.com", TOKEN));
      expect(posture.e8).toBeNull();
      expect(posture.ism.counts.met).toBe(1);
    }
    setEgressTransport(async (_input, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.params.name === "essential_eight_summary") return new Response("", { status: 429 });
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { isError: false, content: [], structuredContent: body.params.name === "ism_status" ? ISM : MITRE } }), { status: 200 });
    });
    await expect(fetchPosture(mcpClient("https://wedgetail.example.com", TOKEN))).rejects.toThrow(/rate limited/);
  });

  it("reports refused tokens as permanent and never echoes the response body", async () => {
    setEgressTransport(async () => new Response(`denied ${TOKEN}`, { status: 401 }));
    const call = mcpClient("https://wedgetail.example.com", TOKEN);
    const err = await call("ism_status", {}).catch((e: WedgetailApiError) => e);
    expect(err).toBeInstanceOf(WedgetailApiError);
    expect((err as WedgetailApiError).permanent).toBe(true);
    expect((err as Error).message).not.toContain(TOKEN);
    setEgressTransport(async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { isError: true, content: [{ type: "text", text: "role too low" }] } }), { status: 200 }));
    await expect(call("ism_status", {})).rejects.toThrow(/role too low/);
    setEgressTransport(async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "{}" }] } }), { status: 200 }));
    await expect(call("ism_status", {})).rejects.toThrow(/no structured result/);
  });
});
