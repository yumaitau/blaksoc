import { and, ilike, inArray, isNull, or } from "drizzle-orm";
import { attackTechniques, sigmaRules } from "@/db/schema";
import { can, type AccessContext } from "@/lib/auth/access";
import { getAlert, listAlerts } from "@/lib/services/alerts";
import { getAsset, listAssets } from "@/lib/services/assets";
import { scoped } from "@/lib/services/common";
import { addNote, getIncident, listIncidents } from "@/lib/services/incidents";
import { searchIntel } from "@/lib/services/intel";
import { patchPriorities } from "@/lib/services/vulnerabilities";
import { requestFromUser } from "@/lib/soar/response";
import { isResponseAction } from "@/lib/soar/actions";
import type { Citation } from "@/db/schema";
import type { ToolSpec } from "./types";

export type ToolContext = { ctx: AccessContext; tenantId: string; allowWrites: boolean };
export type ToolOutput = { data: unknown; citations: Citation[] };
type Tool = ToolSpec & { mode: "read" | "write" | "propose"; run: (args: Record<string, unknown>, t: ToolContext) => Promise<ToolOutput> };

const str = (d: string) => ({ type: "string", description: d });
const obj = (props: Record<string, unknown>, required: string[] = []) => ({ type: "object", properties: props, required });
const cite = (type: string, id: string, label: string): Citation => ({ type, id, label });

/**
 * Tools run with the analyst's own AccessContext, pinned to one tenant, so RBAC and RLS
 * apply exactly as in the UI. Write tools need the analyst to enable writes; destructive
 * actions can only be proposed — they land in the human approval queue.
 */
export const TOOLS: Tool[] = [
  {
    name: "search_alerts", mode: "read", description: "Search alerts in the current tenant.",
    parameters: obj({ q: str("free text"), status: str("comma-separated statuses"), technique: str("ATT&CK id prefix"), sinceHours: { type: "number" } }),
    run: async (a, t) => {
      const { rows } = await listAlerts(t.ctx, { tenantIds: [t.tenantId], q: a.q as string, technique: a.technique as string, sinceHours: (a.sinceHours as number) ?? 168, status: a.status ? (String(a.status).split(",") as never) : undefined, limit: 25 });
      return { data: rows.map((r) => ({ id: r.id, title: r.title, severity: r.severity, risk: r.riskScore, status: r.status, asset: r.assetName, user: r.userName, intel: r.intelVerdict, attack: r.attackTechniques, at: r.occurredAt })), citations: rows.map((r) => cite("alert", r.id, r.title)) };
    },
  },
  {
    name: "get_alert", mode: "read", description: "Full detail of one alert including risk factors, observables and intel.",
    parameters: obj({ id: str("alert id") }, ["id"]),
    run: async (a, t) => {
      const r = await getAlert(t.ctx, String(a.id));
      if (!r || r.alert.tenantId !== t.tenantId) return { data: "not found", citations: [] };
      const { raw: _raw, ...alert } = r.alert;
      return { data: { alert, asset: r.asset && { id: r.asset.id, name: r.asset.name, criticality: r.asset.criticality, exposure: r.asset.exposure }, observables: r.observables, related: r.related }, citations: [cite("alert", r.alert.id, r.alert.title), ...(r.asset ? [cite("asset", r.asset.id, r.asset.name)] : [])] };
    },
  },
  {
    name: "search_assets", mode: "read", description: "Search assets by name, hostname or IP.",
    parameters: obj({ q: str("query") }),
    run: async (a, t) => {
      const rows = await listAssets(t.ctx, { tenantIds: [t.tenantId], q: a.q as string, limit: 25 });
      return { data: rows, citations: rows.map((r) => cite("asset", r.id, r.name)) };
    },
  },
  {
    name: "get_asset", mode: "read", description: "Asset detail: alerts, vulnerabilities, incidents, sightings.",
    parameters: obj({ id: str("asset id") }, ["id"]),
    run: async (a, t) => {
      const r = await getAsset(t.ctx, String(a.id));
      if (!r || r.asset.tenantId !== t.tenantId) return { data: "not found", citations: [] };
      return { data: { asset: r.asset, alerts: r.alerts.slice(0, 15), vulnerabilities: r.vulnerabilities.slice(0, 15).map((v) => ({ cve: v.cve, priority: v.priorityScore })), incidents: r.incidents }, citations: [cite("asset", r.asset.id, r.asset.name)] };
    },
  },
  {
    name: "search_incidents", mode: "read", description: "List incidents (open by default).",
    parameters: obj({ includeClosed: { type: "boolean" } }),
    run: async (a, t) => {
      const rows = await listIncidents(t.ctx, { tenantIds: [t.tenantId], open: !a.includeClosed, limit: 25 });
      return { data: rows, citations: rows.map((r) => cite("incident", r.id, `INC-${r.ref} ${r.title}`)) };
    },
  },
  {
    name: "get_incident", mode: "read", description: "Incident with alerts, timeline, links and actions.",
    parameters: obj({ id: str("incident id") }, ["id"]),
    run: async (a, t) => {
      const r = await getIncident(t.ctx, String(a.id));
      if (!r || r.incident.tenantId !== t.tenantId) return { data: "not found", citations: [] };
      return { data: { incident: r.incident, alerts: r.alerts, timeline: r.timeline, links: r.links, actions: r.actions, tasks: r.tasks }, citations: [cite("incident", r.incident.id, `INC-${r.incident.ref}`), ...r.alerts.map((x) => cite("alert", x.id, x.title))] };
    },
  },
  {
    name: "query_opencti", mode: "read", description: "Search OpenCTI (threat actors, malware, reports, indicators, vulnerabilities).",
    parameters: obj({ term: str("search term"), types: { type: "array", items: { type: "string" } } }, ["term"]),
    run: async (a, t) => {
      const r = await searchIntel(t.ctx, String(a.term), a.types as string[] | undefined);
      return { data: r.configured ? r.results.slice(0, 10) : "OpenCTI not configured", citations: r.results.slice(0, 10).map((x) => cite("opencti", x.id, x.name)) };
    },
  },
  {
    name: "search_indicators", mode: "read", description: "Look up an indicator value (IP, domain, hash, URL) in OpenCTI.",
    parameters: obj({ value: str("indicator value") }, ["value"]),
    run: async (a, t) => {
      const r = await searchIntel(t.ctx, String(a.value), ["Indicator"]);
      return { data: r.results, citations: r.results.map((x) => cite("opencti", x.id, x.name)) };
    },
  },
  {
    name: "search_vulnerabilities", mode: "read", description: "Patch-first vulnerability list for the tenant with KEV/EPSS evidence.",
    parameters: obj({ kevOnly: { type: "boolean" } }),
    run: async (a, t) => {
      const rows = await patchPriorities(t.ctx, { tenantIds: [t.tenantId], kevOnly: !!a.kevOnly, limit: 20 });
      return { data: rows, citations: rows.map((r) => cite("cve", r.cve, r.cve)) };
    },
  },
  {
    name: "query_attack", mode: "read", description: "Look up MITRE ATT&CK techniques by id or name.",
    parameters: obj({ q: str("technique id or name") }, ["q"]),
    run: async (a, t) => {
      const q = String(a.q);
      const rows = await scoped(t.ctx, "detection:read", (tx) => tx.select().from(attackTechniques).where(or(ilike(attackTechniques.id, `${q}%`), ilike(attackTechniques.name, `%${q}%`))).limit(10), [t.tenantId]);
      return { data: rows, citations: rows.map((r) => cite("attack", r.id, `${r.id} ${r.name}`)) };
    },
  },
  {
    name: "search_detection_rules", mode: "read", description: "Find Sigma rules by title or ATT&CK technique.",
    parameters: obj({ q: str("title text or technique id") }, ["q"]),
    run: async (a, t) => {
      const q = String(a.q);
      const rows = await scoped(t.ctx, "detection:read", (tx) =>
        tx.select({ id: sigmaRules.id, title: sigmaRules.title, techniques: sigmaRules.attackTechniques, severity: sigmaRules.severity, enabled: sigmaRules.enabled }).from(sigmaRules)
          .where(and(or(isNull(sigmaRules.tenantId), inArray(sigmaRules.tenantId, [t.tenantId])), or(ilike(sigmaRules.title, `%${q}%`), ilike(sigmaRules.description, `%${q}%`)))).limit(15), [t.tenantId]);
      return { data: rows, citations: rows.map((r) => cite("rule", r.id, r.title)) };
    },
  },
  {
    name: "create_case_note", mode: "write", description: "Add an internal, AI-labelled note to an incident. Requires the analyst to have enabled writes.",
    parameters: obj({ incidentId: str("incident id"), body: str("note text") }, ["incidentId", "body"]),
    run: async (a, t) => {
      const n = await addNote(t.ctx, String(a.incidentId), String(a.body), "internal", true);
      return { data: { noteId: n.id }, citations: [cite("incident", String(a.incidentId), "note added")] };
    },
  },
  {
    name: "draft_incident_report", mode: "read", description: "Gather incident facts for a report draft. Returns data only; the draft is not saved.",
    parameters: obj({ incidentId: str("incident id") }, ["incidentId"]),
    run: async (a, t) => TOOLS.find((x) => x.name === "get_incident")!.run({ id: a.incidentId }, t),
  },
  {
    name: "propose_response_action", mode: "propose", description: "Propose a containment action (isolate_endpoint, disable_identity, block_ioc, …). Always queued for human approval; never executes directly.",
    parameters: obj({ action: str("action key"), assetId: str("asset id"), identity: str("identity"), observable: str("ioc"), reason: str("why"), incidentId: str("incident id") }, ["action", "reason"]),
    run: async (a, t) => {
      if (!isResponseAction(String(a.action))) return { data: `unknown action ${a.action}`, citations: [] };
      if (!can(t.ctx, "response:request", t.tenantId)) return { data: "analyst lacks response:request", citations: [] };
      // Recorded as AI-originated: destructive actions always wait for a human decision.
      const r = await requestFromUser(t.ctx, { tenantId: t.tenantId, action: a.action as never, target: { assetId: a.assetId as string, identity: a.identity as string, observable: a.observable as string }, reason: `[AI proposal] ${a.reason}`, incidentId: (a.incidentId as string) ?? null }, "ai");
      return { data: { actionId: r.action.id, status: r.needsApproval ? "awaiting human approval" : "queued" }, citations: [] };
    },
  },
];

export function toolsFor(allowWrites: boolean): Tool[] {
  return TOOLS.filter((t) => t.mode === "read" || (allowWrites && (t.mode === "write" || t.mode === "propose")));
}
