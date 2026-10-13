import { z } from "zod";
import { egressFetch } from "@/lib/net/egress";

/**
 * Pulls a Wedgetail install's own ISM control status and ATT&CK rule coverage over its MCP endpoint
 * (POST <console>/mcp, Streamable HTTP, stateless JSON). The install's REST API accepts only console
 * sessions, so a read-only `wtp_` token on MCP is the supported machine path. Only aggregate fields are
 * kept: no account IDs, rule parameters, attestations or people.
 */
export const WEDGETAIL_TOKEN = /^wtp_[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;
const MAX_BYTES = 2 * 1024 * 1024;

export class WedgetailApiError extends Error {
  constructor(message: string, readonly permanent = false) {
    super(message);
    this.name = "WedgetailApiError";
  }
}

const ISM_STATUSES = ["met", "partial", "not_met", "not_applicable"] as const;
export type IsmStatus = (typeof ISM_STATUSES)[number];

const ismResponse = z.object({
  release: z.object({ name: z.string().max(200), oscal: z.string().max(100).optional(), mapVersion: z.string().max(100).optional() }),
  generatedAt: z.string().max(40),
  controls: z.array(z.object({
    id: z.string().regex(/^ISM-\d{4}$/),
    title: z.string().max(500),
    topic: z.string().max(60),
    responsibility: z.string().max(40),
    status: z.enum(ISM_STATUSES),
    reason: z.string().max(2000),
    e8: z.array(z.number().int().min(1).max(3)).max(3).optional(),
    withdrawn: z.literal(true).optional(),
    detections: z.object({ mapped: z.number().int().nonnegative(), active: z.number().int().nonnegative() }).optional(),
  })).max(500),
});

const techniqueId = z.string().regex(/^(?:T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?)$/);
const mitreCoverage = z.object({
  version: z.string().max(40),
  tactics: z.array(z.object({
    techniques: z.array(z.object({ id: techniqueId, rules: z.array(z.string().max(200)).max(1000), hunting: z.array(z.string().max(200)).max(1000) })).max(2000),
  })).max(40),
  other: z.array(z.object({ id: techniqueId, rules: z.array(z.string().max(200)).max(1000), hunting: z.array(z.string().max(200)).max(1000) })).max(2000).default([]),
  gaps: z.array(z.object({ id: techniqueId })).max(2000),
  totals: z.object({ techniques: z.number().int(), covered: z.number().int(), relevant: z.number().int(), relevantCovered: z.number().int() }),
});

export type WedgetailIsm = {
  release: string;
  generatedAt: string;
  counts: Record<IsmStatus, number>;
  controls: { id: string; title: string; topic: string; responsibility: string; status: IsmStatus; reason: string; e8: number[]; withdrawn: boolean; detections: { mapped: number; active: number } | null }[];
};
export type WedgetailMitre = {
  version: string;
  totals: { techniques: number; covered: number; relevant: number; relevantCovered: number };
  /** Techniques with at least one enabled rule (rules) or hunting query (hunting). */
  techniques: { id: string; rules: number; hunting: number }[];
  gaps: string[];
};

export function parseIsm(value: unknown): WedgetailIsm {
  const data = ismResponse.parse(value);
  const counts = Object.fromEntries(ISM_STATUSES.map((s) => [s, 0])) as Record<IsmStatus, number>;
  for (const c of data.controls) counts[c.status]++;
  return {
    release: data.release.name,
    generatedAt: data.generatedAt,
    counts,
    controls: data.controls.map((c) => ({ id: c.id, title: c.title, topic: c.topic, responsibility: c.responsibility, status: c.status, reason: c.reason, e8: c.e8 ?? [], withdrawn: !!c.withdrawn, detections: c.detections ?? null })),
  };
}

export function parseMitre(value: unknown): WedgetailMitre | null {
  if (value && typeof value === "object" && (value as { available?: unknown }).available === false) return null;
  const data = mitreCoverage.parse(value);
  const byId = new Map<string, { id: string; rules: number; hunting: number }>();
  for (const t of [...data.tactics.flatMap((tactic) => tactic.techniques), ...data.other]) {
    if (!t.rules.length && !t.hunting.length) continue;
    // A technique sits under each of its tactics; count its rules once.
    const prev = byId.get(t.id);
    byId.set(t.id, { id: t.id, rules: Math.max(prev?.rules ?? 0, t.rules.length), hunting: Math.max(prev?.hunting ?? 0, t.hunting.length) });
  }
  return { version: data.version, totals: data.totals, techniques: [...byId.values()].sort((a, b) => a.id.localeCompare(b.id)), gaps: [...new Set(data.gaps.map((g) => g.id))] };
}

/** The install's console origin, which serves /mcp. HTTPS only; the path is fixed here. */
export function mcpEndpoint(consoleUrl: string): URL {
  const url = new URL(consoleUrl);
  if (url.protocol !== "https:") throw new WedgetailApiError("The Wedgetail console URL must use HTTPS.", true);
  if (url.username || url.password) throw new WedgetailApiError("The Wedgetail console URL must not contain credentials.", true);
  return new URL("/mcp", url.origin);
}

export type McpCall = (tool: string, args: Record<string, unknown>) => Promise<unknown>;

/** One stateless JSON-RPC tools/call. No Origin header: the install refuses foreign origins. */
export function mcpClient(consoleUrl: string, token: string, timeoutMs = 20_000): McpCall {
  if (!WEDGETAIL_TOKEN.test(token)) throw new WedgetailApiError("The Wedgetail MCP token is not a wtp_ token.", true);
  const endpoint = mcpEndpoint(consoleUrl);
  let id = 0;
  return async (tool, args) => {
    const res = await egressFetch(endpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method: "tools/call", params: { name: tool, arguments: args } }),
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    }, "public");
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new WedgetailApiError("Wedgetail returned more data than expected.");
    // Never echo the body: an error page could reflect the request.
    if (res.status === 401 || res.status === 403) throw new WedgetailApiError(`Wedgetail refused the token (HTTP ${res.status}). Issue a new read-only MCP token.`, true);
    if (res.status === 429) throw new WedgetailApiError("Wedgetail rate limited the request (HTTP 429).");
    if (!res.ok) throw new WedgetailApiError(`Wedgetail MCP returned HTTP ${res.status}.`, res.status === 404 || res.status === 405);
    let body: { result?: { isError?: boolean; structuredContent?: unknown; content?: { type: string; text?: string }[] }; error?: { message?: string } };
    try {
      body = JSON.parse(text);
    } catch {
      throw new WedgetailApiError("Wedgetail MCP did not return JSON.");
    }
    if (body.error) throw new WedgetailApiError(`Wedgetail MCP error: ${String(body.error.message ?? "unknown").slice(0, 200)}`, true);
    const result = body.result;
    if (!result) throw new WedgetailApiError("Wedgetail MCP returned no result.");
    if (result.isError) throw new WedgetailApiError(`Wedgetail tool ${tool} failed: ${String(result.content?.[0]?.text ?? "").slice(0, 200)}`);
    if (result.structuredContent !== undefined) return result.structuredContent;
    throw new WedgetailApiError(`Wedgetail tool ${tool} returned no structured result.`);
  };
}

export type WedgetailPosture = { ism: WedgetailIsm; mitre: WedgetailMitre | null };

export async function fetchPosture(call: McpCall): Promise<WedgetailPosture> {
  const ism = parseIsm(await call("ism_status", {}));
  const mitre = parseMitre(await call("mitre_coverage", {}));
  return { ism, mitre };
}
