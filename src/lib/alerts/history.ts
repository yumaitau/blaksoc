import { ruleById } from "@/lib/correlation/rules";
import { isResponseAction, RESPONSE_ACTIONS } from "@/lib/soar/actions";
import { sourceLabel } from "./provenance";

/** An audit row about an alert, its response actions, playbook runs or incident membership. */
export type AlertAuditRow = {
  id: number;
  at: Date;
  action: string;
  actorId: string | null;
  actorKind: string;
  actorName: string | null;
  targetType: string | null;
  targetId: string | null;
  detail: unknown;
};

/** Names the sentences need that the audit row only holds as ids. */
export type HistoryRefs = {
  users: ReadonlyMap<string, string>;
  incidents: ReadonlyMap<string, number>;
  /** Response action id → action key (isolate_endpoint, …). */
  responseActions: ReadonlyMap<string, string>;
};

export type HistoryEntry = { key: string; at: Date; actor: string; text: string; href?: string };

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : null);
const clip = (s: string, max = 160) => (s.length > max ? `${s.slice(0, max - 1)}…` : s);
const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** "FALSE_POSITIVE" → "false positive". */
export const statusWords = (s: unknown) => (str(s) ?? "unknown").replaceAll("_", " ").toLowerCase();

export function actorLabel(kind: string, name: string | null): string {
  if (kind === "system") return "system";
  if (kind === "playbook") return "playbook";
  if (kind === "ai") return name ? `AI analyst (for ${name})` : "AI analyst";
  if (kind === "service") return name ?? "API client";
  return name ?? "unknown user";
}

function responseLabel(row: AlertAuditRow, refs: HistoryRefs): string {
  const key = str(obj(row.detail).action) ?? (row.targetId ? refs.responseActions.get(row.targetId) : undefined) ?? null;
  const label = key && isResponseAction(key) ? RESPONSE_ACTIONS[key].label : key;
  return label ? `“${label}”` : "a response action";
}

function incidentRef(row: AlertAuditRow, refs: HistoryRefs): { name: string; href?: string } {
  const ref = row.targetId ? refs.incidents.get(row.targetId) : undefined;
  return ref != null ? { name: `incident INC-${ref}`, href: `/soc/incidents/${row.targetId}` } : { name: "an incident" };
}

/** One audit row as a plain sentence (no subject; the actor is shown beside it). Unknown actions fall back to the raw action name. */
export function describeAuditEntry(row: AlertAuditRow, refs: HistoryRefs): { text: string; href?: string } {
  const d = obj(row.detail);
  switch (row.action) {
    case "alert.update": {
      const parts: string[] = [];
      if (str(d.status)) parts.push(str(d.from) && d.from !== d.status ? `changed status from ${statusWords(d.from)} to ${statusWords(d.status)}` : `set status to ${statusWords(d.status)}`);
      if ("assigneeId" in d) {
        const who = str(d.assigneeId);
        parts.push(!who ? "unassigned the alert" : who === row.actorId ? "took the alert" : `assigned it to ${refs.users.get(who) ?? "another analyst"}`);
      }
      return { text: parts.length ? capital(parts.join(" and ")) : "Updated the alert" };
    }
    case "correlation.finding": {
      const ruleId = str(d.ruleId);
      const title = ruleId ? (ruleById(ruleId)?.title ?? ruleId) : "a correlation rule";
      const n = Array.isArray(d.eventIds) ? d.eventIds.length : 0;
      return { text: `Raised by correlation rule “${title}”${n ? ` from ${n} alert${n === 1 ? "" : "s"}` : ""}` };
    }
    case "incident.create": {
      const inc = incidentRef(row, refs);
      const others = Array.isArray(d.alertIds) ? d.alertIds.length - 1 : 0;
      return { text: `Opened ${inc.name}${others > 0 ? ` with ${others} other alert${others === 1 ? "" : "s"}` : ""}`, href: inc.href };
    }
    case "incident.add_alerts": {
      const inc = incidentRef(row, refs);
      return { text: `Added to ${inc.name}`, href: inc.href };
    }
    case "incident.ungroup": {
      const inc = incidentRef(row, refs);
      return { text: `Removed from ${inc.name}${d.closed === true ? "; the incident was closed" : ""}`, href: inc.href };
    }
    case "response.request":
      return { text: `Requested ${responseLabel(row, refs)}${d.needsApproval === true ? " (awaiting approval)" : ""}` };
    case "approval.approved":
      return { text: `Approved ${responseLabel(row, refs)}` };
    case "approval.rejected":
      return { text: `Rejected ${responseLabel(row, refs)}` };
    case "approval.expired":
      return { text: `Approval for ${responseLabel(row, refs)} expired` };
    case "response.dispatch":
      return { text: `Sent ${responseLabel(row, refs)} to the provider` };
    case "response.execute": {
      const msg = str(d.message);
      return { text: d.ok === true ? `${capital(responseLabel(row, refs))} completed` : `${capital(responseLabel(row, refs))} failed${msg ? `: ${clip(msg)}` : ""}` };
    }
    case "response.stale_fail":
      return { text: `${capital(responseLabel(row, refs))} failed: approval went stale before it ran` };
    case "playbook.start":
      return { text: `Playbook “${str(d.playbook) ?? "unknown"}” started${str(d.event) === "alert.created" ? " when the alert was created" : ""}` };
    case "playbook.run_manual":
      return { text: `Ran playbook “${str(d.playbook) ?? "unknown"}”` };
    case "alert.lane":
      return { text: d.lane === "active" ? "Moved it from the passive lane back to the active queue" : "Moved it to the passive lane" };
    case "noise_rule.create":
    case "noise_rule.approve": {
      const why = str(d.reason);
      const verb = row.action === "noise_rule.approve" ? "Approved a noise rule" : "Created a noise rule";
      return { text: `${verb}${why ? ` (“${clip(why, 120)}”)` : ""}; moved this alert to the passive lane`, href: "/soc/tuning" };
    }
    case "tuning.close": {
      const why = str(d.reason);
      return { text: `Closed it as a false positive${why ? ` (“${clip(why, 120)}”)` : ""}`, href: "/soc/hermes" };
    }
    case "tuning.undo":
      return { text: "Undid the automated closure; the alert was reopened", href: "/soc/hermes" };
    default:
      return { text: row.action };
  }
}

/**
 * The alert's history, oldest first. Ingest is not audited, so its creation is synthesised from
 * `ingestedAt` as the first entry.
 */
export function alertHistory(
  alert: { ingestedAt: Date; severity: string; source: string; integrationName: string | null; lane?: string; passiveReason?: string | null },
  rows: AlertAuditRow[],
  refs: HistoryRefs,
): HistoryEntry[] {
  const created: HistoryEntry = {
    key: "ingest",
    at: alert.ingestedAt,
    actor: "system",
    text: `Stored as a ${alert.severity} alert from ${alert.integrationName ?? sourceLabel(alert.source)}`,
  };
  // Passive from the start: a noise rule matched at ingest (which is not audited); later moves have their own rows.
  if (alert.lane === "passive" && !rows.some((r) => r.action === "alert.lane" || r.action.startsWith("noise_rule."))) {
    created.text += ` in the passive lane${alert.passiveReason ? ` (${clip(alert.passiveReason, 120)})` : ""}`;
  }
  const rest = [...rows]
    .sort((a, b) => a.at.getTime() - b.at.getTime() || a.id - b.id)
    .map((r): HistoryEntry => ({ key: String(r.id), at: r.at, actor: actorLabel(r.actorKind, r.actorName), ...describeAuditEntry(r, refs) }));
  return [created, ...rest];
}
