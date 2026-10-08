import { RESPONSE_ACTIONS } from "@/lib/soar/actions";

/**
 * Plain-language audit entries. Pure: no database, no React, so the audit trail, its CSV
 * export and per-record history panels all word the same action the same way.
 */

export type DescribableAuditEntry = {
  action: string;
  actorKind?: string | null;
  tenantId?: string | null;
  targetType?: string | null;
  targetId?: string | null;
  detail?: unknown;
};

export type AuditDescription = { summary: string; targetHref?: string };

/** User id → display name, for people a detail mentions (assignee, owner, role holder). */
export type AuditNames = Readonly<Record<string, string>>;

type Detail = Record<string, unknown>;
type Ctx = { d: Detail; e: DescribableAuditEntry; who: (id: unknown) => string };
type Describer = string | ((c: Ctx) => string);

const REDACTED = "[redacted]";

/** Words that mark a field as secret wherever they appear in its name. */
const SECRET_WORDS = new Set(["password", "passwd", "passphrase", "pwd", "secret", "secrets", "token", "tokens", "ciphertext", "credential", "credentials", "cookie", "cookies", "authorization", "apikey", "privatekey", "accesskey", "secretkey"]);
/** "key" is secret on its own or after one of these ("apiKey", "private_key"), not in "roleKey" or "dedupeKey". */
const KEY_QUALIFIERS = new Set(["api", "private", "access", "secret", "signing", "encryption", "client", "shared", "master", "session", "licence", "license", "auth"]);

const words = (name: string) => name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

/** Whether a field name looks like it holds a secret (password, secret, token, key, ciphertext…). */
export function isSecretKey(name: string): boolean {
  const w = words(name);
  if (w.some((x) => SECRET_WORDS.has(x))) return true;
  return w.some((x, i) => (x === "key" || x === "keys") && (w.length === 1 || (i > 0 && KEY_QUALIFIERS.has(w[i - 1]!))));
}

/** Copy of an audit detail with the value of every secret-looking field replaced. */
export function redactAuditDetail(value: unknown, depth = 0): unknown {
  if (depth > 12) return REDACTED;
  if (Array.isArray(value)) return value.map((v) => redactAuditDetail(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Detail).map(([k, v]) => [k, isSecretKey(k) ? REDACTED : redactAuditDetail(v, depth + 1)]));
  }
  return value;
}

const str = (v: unknown, max = 80) => {
  if (typeof v !== "string" || !v.trim()) return undefined;
  const s = v.trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};
const obj = (v: unknown): Detail => (v && typeof v === "object" && !Array.isArray(v) ? (v as Detail) : {});
const howMany = (v: unknown) => (Array.isArray(v) ? v.length : typeof v === "number" && Number.isFinite(v) ? v : undefined);
const count = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString("en-AU")} ${n === 1 ? one : many}`;
const quote = (v: unknown) => (str(v) ? `“${str(v)}”` : "");
const named = (noun: string, v: unknown) => (str(v) ? `${noun} ${quote(v)}` : noun);
/** IN_PROGRESS → "in progress". */
const status = (v: unknown) => (str(v) ?? "unknown").replaceAll("_", " ").toLowerCase();
/** rootCause / root_cause → "root cause". */
const field = (k: string) => (k === "secretCiphertext" || k === "secrets" ? "credentials" : k === "collaboratorIds" ? "collaborators" : k === "ownerId" ? "owner" : words(k).join(" "));
const fields = (ks: string[]) => list(ks.map(field));
const list = (xs: string[]) => (xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);
const sentence = (parts: string[], fallback: string) => {
  const s = list(parts.filter(Boolean));
  return s ? s[0]!.toUpperCase() + s.slice(1) : fallback;
};
const role = (v: unknown) => (str(v) ?? "unknown").replaceAll("_", " ");
const responseLabel = (v: unknown) => (typeof v === "string" && Object.hasOwn(RESPONSE_ACTIONS, v) ? RESPONSE_ACTIONS[v as keyof typeof RESPONSE_ACTIONS].label : str(v) ? status(v) : "unknown action");
const approvalKind = (t: string | null | undefined) => (t === "playbook_step" ? "playbook step" : t === "response_action" ? "response action" : "request");
const onOff = (v: unknown, on: string, off: string) => (v === false ? off : on);
const brief = (v: unknown): string | undefined =>
  typeof v === "boolean" ? (v ? "on" : "off") : typeof v === "number" ? String(v) : typeof v === "string" && v.length <= 40 ? v : undefined;

/** Top-level fields that differ between two settings objects, with old → new for short values. */
function changes(before: unknown, after: unknown): string[] {
  const b = obj(before);
  const a = obj(after);
  const keys = [...new Set([...Object.keys(b), ...Object.keys(a)])].filter((k) => JSON.stringify(b[k]) !== JSON.stringify(a[k]));
  return keys.map((k) => {
    const [from, to] = [brief(b[k]), brief(a[k])];
    return !isSecretKey(k) && from !== undefined && to !== undefined ? `${field(k)} ${from} → ${to}` : field(k);
  });
}

function incidentUpdate({ d, who }: Ctx): string {
  const p = obj(d.patch);
  const parts: string[] = [];
  if (p.status !== undefined) parts.push(`set the incident status to ${status(p.status)}`);
  if (p.severity !== undefined) parts.push(`set severity to ${status(p.severity)}`);
  if ("ownerId" in p) parts.push(p.ownerId ? `assigned it to ${who(p.ownerId)}` : "unassigned it");
  if (str(p.title)) parts.push(`renamed it ${quote(p.title)}`);
  const rest = Object.keys(p).filter((k) => !["status", "severity", "ownerId", "title"].includes(k));
  if (rest.length) parts.push(`updated ${fields(rest)}`);
  return sentence(parts, "Updated the incident");
}

function alertUpdate({ d, who }: Ctx): string {
  const parts: string[] = [];
  const to = str(d.status);
  const from = str(d.from);
  if (to) parts.push(from && from !== to ? `changed alert status from ${status(from)} to ${status(to)}` : `set alert status to ${status(to)}`);
  if ("assigneeId" in d) parts.push(d.assigneeId ? `assigned the alert to ${who(d.assigneeId)}` : "unassigned the alert");
  return sentence(parts, "Updated the alert");
}

const DESCRIBE: Record<string, Describer> = {
  // Sign-in and credentials
  "auth.passkey.add": "Added a passkey",
  "auth.passkey.delete": "Removed a passkey",
  "sso.register": ({ d }) => `Registered ${str(d.protocol)?.toUpperCase() ?? "an"} identity provider${str(d.domain) ? ` for ${str(d.domain)}` : ""}`,

  // People and roles
  "rbac.assign": ({ d, e, who }) => `Granted the ${role(d.roleKey)} role to ${who(e.targetId)}${d.tenantId ? "" : " (platform-wide)"}`,
  "rbac.revoke": ({ d, e, who }) => `Revoked the ${role(d.roleKey)} role from ${who(e.targetId)}`,
  "rbac.role_create": ({ d, e }) => `Created the custom role ${quote(d.name ?? e.targetId)}`,
  "user.provision": ({ d, e, who }) => `Provisioned an account for ${str(d.email) ?? who(e.targetId)}`,
  "user.disable": ({ e, who }) => `Disabled the account of ${who(e.targetId)}`,
  "user.enable": ({ e, who }) => `Re-enabled the account of ${who(e.targetId)}`,
  "service_identity.create": ({ d }) => `Created ${named("service identity", d.name)}${howMany(d.scopes) ? ` with ${count(howMany(d.scopes)!, "scope")}` : ""}`,
  "service_identity.rotate": ({ d }) => `Rotated the secret of ${named("service identity", d.name)}`,
  "service_identity.enable": ({ d }) => `Enabled ${named("service identity", d.name)}`,
  "service_identity.disable": ({ d }) => `Disabled ${named("service identity", d.name)}`,
  "service_identity.revoke": ({ d }) => `Revoked ${named("service identity", d.name)}`,
  "api.token": "Issued an API access token",
  "api.token_denied": ({ d }) => `Refused an API access token${str(d.reason) ? ` (${str(d.reason)})` : ""}`,
  "api.request": ({ d, e }) => `API call${str(e.targetId ?? d.path) ? ` ${str(e.targetId ?? d.path)}` : ""}${typeof d.status === "number" ? ` returned ${d.status}` : ""}`,

  // Customers and settings
  "tenant.create": ({ d }) => `Created ${named("customer", d.name)}`,
  "tenant.settings": ({ d }) => {
    const c = changes(d.before, d.after);
    return c.length ? `Changed customer settings: ${list(c)}` : "Saved customer settings (no changes)";
  },
  "plan.update": "Changed the customer's service plan",
  "partner.consent": "Consented to partner access",
  "partner.revoke": "Revoked partner access",
  "partner.brand": ({ d }) => `Set the partner brand${str(d.brandName) ? ` to ${quote(d.brandName)}` : ""}`,
  "partner.escalate": "Escalated to the partner",
  "governance.propose": "Proposed a governance change",
  "governance.approve": "Approved a governance change",
  "governance.reject": "Rejected a governance change",
  "governance.apply": "Applied an approved governance change",
  "governance.notify": "Notified a governance steward",
  "governance.initialise": "Set up governance",
  "health.policy": "Changed the sensor health policy",
  "health.site": "Changed a site's health settings",
  "escalation.update": "Changed the escalation contacts",

  // Integrations
  "integration.create": ({ d }) => `Added ${str(d.provider) ? `the ${str(d.provider)} integration` : "an integration"}${str(d.name) ? ` ${quote(d.name)}` : ""}`,
  "integration.update": ({ d }) => (Array.isArray(d.fields) && d.fields.length ? `Updated the integration's ${fields(d.fields.map(String))}` : "Updated the integration"),
  "integration.test": ({ d }) => `Tested the integration connection: ${d.ok ? "passed" : "failed"}`,
  "integration.link_tenant": "Linked the integration to a customer",
  "kelpie.case_push": ({ d }) => `Pushed the incident to Kelpie${str(d.caseNumber) ? ` as case ${str(d.caseNumber)}` : ""}`,
  "kelpie.case_sync": "Synced the incident from Kelpie",

  // Alerts and incidents
  "alert.update": alertUpdate,
  "correlation.finding": ({ d }) => `Correlation rule${str(d.ruleId) ? ` ${str(d.ruleId)}` : ""} raised an alert${howMany(d.eventIds) ? ` from ${count(howMany(d.eventIds)!, "event")}` : ""}`,
  "correlation.rule_toggle": ({ d }) => `${onOff(d.enabled, "Enabled", "Disabled")} a correlation rule`,
  "alert.lane": ({ d }) => (d.lane === "active" ? "Moved the alert back to the active queue" : "Moved the alert to the passive lane"),

  // Noise tuning and the Hermes tuning agent
  "noise_rule.create": ({ d }) => `Created a noise rule${str(d.scope) ? ` for ${str(d.scope, 120)}` : ""}${howMany(d.alertIds) ? `; ${count(howMany(d.alertIds)!, "open alert")} moved to the passive lane` : ""}`,
  "noise_rule.approve": ({ d }) => `Approved a proposed noise rule${howMany(d.alertIds) ? `; ${count(howMany(d.alertIds)!, "open alert")} moved to the passive lane` : ""}`,
  "noise_rule.reject": "Rejected a proposed noise rule",
  "noise_rule.expire": "Expired a noise rule",
  "noise_rule.extend": ({ d }) => `Extended a noise rule${str(d.to) ? ` to ${str(d.to)!.slice(0, 10)}` : ""}`,
  "tuning.switch": ({ d }) => `${onOff(d.enabled, "Allowed", "Stopped")} Hermes ${d.enabled === false ? "from acting" : "to act"}`,
  "tuning.annotate": "Hermes annotated an alert pattern",
  "tuning.close": ({ d }) => `Hermes closed ${typeof d.affected === "number" ? count(d.affected, "alert") : "alerts"} as false positives`,
  "tuning.purge": ({ d }) => `Hermes purged ${typeof d.deleted === "number" ? count(d.deleted, "closed alert") : "closed alerts"} past the undo window`,
  "tuning.undo": ({ d }) => `Undid a Hermes ${d.kind === "noise_rule" ? "noise rule" : "closure"}${typeof d.restored === "number" ? ` (${count(d.restored, "alert")} restored)` : ""}`,
  "tuning.report": "Hermes posted a run report",
  "tuning.memory": ({ d }) => `Hermes updated its memory (${[d.added, d.changed, d.removed].every((n) => typeof n === "number") ? `${d.added} added, ${d.changed} changed, ${d.removed} removed` : "changes"})`,
  "tuning.memory_note_add": "Added a note to Hermes' memory",
  "tuning.memory_note_delete": "Deleted a note from Hermes' memory",
  "incident.create": ({ d }) => `Opened an incident${howMany(d.alertIds) ? ` from ${count(howMany(d.alertIds)!, "alert")}` : ""}`,
  "incident.update": incidentUpdate,
  "incident.auto_group": ({ d }) => `Grouped ${howMany(d.alertIds) ? count(howMany(d.alertIds)!, "alert") : "alerts"} into the incident automatically${str(d.reason) ? `: ${str(d.reason)}` : ""}`,
  "incident.add_alerts": ({ d }) => `Added ${howMany(d.alertIds) ? count(howMany(d.alertIds)!, "alert") : "alerts"} to the incident`,
  "incident.ungroup": ({ d }) => `Ungrouped ${howMany(d.alertIds) ? count(howMany(d.alertIds)!, "alert") : "alerts"} from the incident${d.closed ? " and closed it" : ""}`,
  "incident.note": ({ d }) => `Added ${d.visibility === "internal" ? "an internal" : d.visibility === "customer" ? "a customer-visible" : "a"} note${d.aiGenerated ? " (AI-drafted)" : ""}`,
  "incident.timeline_add": ({ d }) => `Added a timeline entry${str(d.title) ? ` ${quote(d.title)}` : ""}`,
  "incident.acknowledge": "Acknowledged the incident",
  "incident.evidence_add": ({ d }) => `Added evidence${str(d.name) ? ` ${quote(d.name)}` : ""}`,
  "dfir.collection_request": "Requested a forensic collection",
  "dfir.collection_complete": "Forensic collection completed",
  "dfir.hunt": "Ran a forensic hunt",
  "record.note": "Added a note",
  "task.create": "Created a task",

  // Response and approvals
  "response.request": ({ d }) => `Requested response: ${responseLabel(d.action)}${d.needsApproval ? " (needs approval)" : d.autoAllowed ? " (automatic containment allowed)" : ""}`,
  "response.dispatch": "Sent the response action to the provider",
  "response.execute": ({ d }) => `Response action ${d.ok ? "succeeded" : "failed"}${!d.ok && str(d.message) ? `: ${str(d.message)}` : ""}`,
  "response.stale_fail": "Did not run a response action: its approval went stale",
  "approval.approved": ({ e }) => `Approved a ${approvalKind(e.targetType)}`,
  "approval.rejected": ({ e }) => `Rejected a ${approvalKind(e.targetType)}`,
  "approval.expired": ({ e }) => `A ${approvalKind(e.targetType)} approval expired without a decision`,

  // Detections and playbooks
  "detection.save": ({ d }) => `Saved ${named("detection", d.title)}${typeof d.version === "number" ? ` (version ${d.version})` : ""}`,
  "detection.enable": "Enabled a detection",
  "detection.disable": "Disabled a detection",
  "detection.deploy": ({ d }) => `Deployed a detection${typeof d.version === "number" ? ` (version ${d.version})` : ""}`,
  "playbook.create": ({ d }) => `Created ${named("playbook", d.name)}`,
  "playbook.update": ({ d }) => `Updated ${named("playbook", d.name)}${typeof d.version === "number" ? ` to version ${d.version}` : ""}`,
  "playbook.enable": ({ d }) => `Enabled ${named("playbook", d.name)}`,
  "playbook.disable": ({ d }) => `Disabled ${named("playbook", d.name)}`,
  "playbook.start": ({ d }) => `Started ${named("playbook", d.playbook)}`,
  "playbook.run_manual": ({ d }) => `Ran ${named("playbook", d.playbook)} manually`,
  "playbook.stale_cancel": "Cancelled a playbook run: its approval went stale",

  // Data lifecycle, reports and the audit trail itself
  "retention.purge_alerts": ({ d }) =>
    `Purged ${howMany(d.deleted) !== undefined ? count(howMany(d.deleted)!, `${str(d.severity) ? `${status(d.severity)} ` : ""}alert`) : "alerts"}${typeof d.retentionDays === "number" ? ` older than ${d.retentionDays} days` : ""}`,
  "report.generate": ({ d }) => `Generated a report${str(d.kind) ? ` (${status(d.kind)})` : ""}`,
  "report.board_deliver": "Delivered the board report",
  "audit.export": ({ d }) => `Exported ${howMany(d.rows) !== undefined ? count(howMany(d.rows)!, "audit entry", "audit entries") : "the audit trail"} to CSV`,

  // Assets, vulnerabilities, intel
  "asset.update": ({ d }) => (Object.keys(d).length ? `Updated the asset's ${fields(Object.keys(d))}` : "Updated the asset"),
  "asset.context": "Viewed asset context",
  "endpoint.context": "Viewed endpoint context",
  "vuln.status": ({ d }) => `Set the vulnerability status to ${status(d.status)}`,
  "sensor.enrol": "Enrolled a network sensor",
  "sensor.ruleset": "Updated a sensor's ruleset",
  "sensor.seen": "Sensor checked in",
  "agent.enrol": "Enrolled an endpoint agent",
  "agent.revoke": "Revoked an endpoint agent",
  "agent.profile": "Changed a site's agent profile",
  "syslog.source_create": ({ d }) => `Added ${named("syslog source", d.name)}`,
  "domain.register": ({ d }) => `Registered ${named("domain", d.name)}`,
  "domain.verify": ({ d }) => `Verified ${named("domain", d.name)}`,
  "asm.attest": ({ d }) => `Attested ownership of ${quote(d.name) || "an exposed asset"}`,
  "intel.enrich": "Enriched observables with threat intelligence",
  "intel.tag": "Tagged threat intelligence",
  "intel.feed_toggle": ({ d }) => `${onOff(d.enabled, "Enabled", "Disabled")} a threat intelligence feed`,
  "intel.entitlement": "Changed threat intelligence entitlement",
  "intel.sighting_request": "Requested a threat intelligence sighting",
  "intel.sighting_created": "Shared a threat intelligence sighting",
  "intel.sighting_refused": "Refused to share a threat intelligence sighting",
  "event.search": "Searched events",
  "event.entity_activity": "Searched an entity's activity",
  "notify.delivery": "Sent a notification",

  // Customer programmes
  "e8.assess": "Recorded an Essential Eight assessment",
  "ir.plan": "Updated the incident response plan",
  "ir.exercise": "Recorded an incident response exercise",
  "awareness.schedule": "Scheduled security awareness training",
  "training.open": "Opened a training workspace",
  "training.start": "Started a training scenario",
  "training.cosign": "Co-signed a trainee's work",
};

const PREFIX: [string, (rest: string, c: Ctx) => string][] = [
  ["auth.", (rest) => `Authentication: ${status(rest.replaceAll(".", " "))}`],
  ["ai.", (rest) => `AI analyst used the ${status(rest)} tool`],
  ["onboarding.", (rest) => `Onboarding: ${status(rest)}`],
  ["obligation.", (rest) => `Notification obligations: ${status(rest)}`],
  ["approval.", (rest) => `Approval ${status(rest)}`],
];

/** Human name for a target type: "playbook_run" → "playbook run". */
export function auditTargetLabel(targetType: string | null | undefined, targetId: string | null | undefined): string {
  if (!targetType) return "—";
  const id = targetId ? (targetId.length > 12 ? `${targetId.slice(0, 8)}…` : targetId) : "";
  return `${targetType === "tenant" ? "customer" : targetType === "sigma_rule" ? "detection" : field(targetType)}${id ? ` ${id}` : ""}`;
}

/** Page for a target, where blakSOC has one. */
export function auditTargetHref(targetType: string | null | undefined, targetId: string | null | undefined): string | undefined {
  if (!targetType || !targetId) return undefined;
  const id = encodeURIComponent(targetId);
  switch (targetType) {
    case "alert": return `/soc/alerts/${id}`;
    case "incident": return `/soc/incidents/${id}`;
    case "integration": return `/integrations/${id}`;
    case "asset": return `/assets/${id}`;
    case "playbook": return `/soar/playbooks/${id}`;
    case "playbook_run": return `/soar/runs/${id}`;
    case "report": return `/reports/${id}`;
    case "sigma_rule": return `/detections/rules/${id}`;
    case "noise_rule": return "/soc/tuning";
    case "tuning_action":
    case "hermes_report":
    case "hermes_memory": return "/soc/hermes";
    case "tenant": return `/soc/alerts?tenant=${id}`;
    // No per-user page: show everything that happened to this person instead.
    case "user": return `/admin/audit?targetType=user&targetId=${id}`;
    default: return undefined;
  }
}

/** Plain-language sentence for an audit entry, and a link to its target when one exists. Unknown actions fall back to the raw key. */
export function describeAuditEntry(entry: DescribableAuditEntry, names: AuditNames = {}): AuditDescription {
  const who = (id: unknown) => (typeof id === "string" && id ? (names[id] ?? `user ${id.slice(0, 8)}`) : "someone");
  const c: Ctx = { d: obj(entry.detail), e: entry, who };
  const exact = Object.hasOwn(DESCRIBE, entry.action) ? DESCRIBE[entry.action] : undefined;
  const prefix = exact === undefined ? PREFIX.find(([p]) => entry.action.startsWith(p) && entry.action.length > p.length) : undefined;
  let summary = entry.action;
  try {
    if (typeof exact === "string") summary = exact;
    else if (exact) summary = exact(c);
    else if (prefix) summary = prefix[1](entry.action.slice(prefix[0].length), c);
  } catch {
    // A detail with an unexpected shape must never break the audit trail.
    summary = entry.action;
  }
  const targetHref = auditTargetHref(entry.targetType, entry.targetId);
  return targetHref ? { summary, targetHref } : { summary };
}

/**
 * Whether Hermes wrote the entry: a service identity acting through the tuning API (any tuning.* action, or a
 * noise rule it created there) or the service identity named Hermes. People's tuning actions (undo, the act
 * switch, memory notes) are theirs, not Hermes'.
 */
/** The service identity Hermes runs as (created at deploy; see deploy/aws/README.md). */
export const HERMES_IDENTITY_NAME = "hermes";

/** True only for Hermes' own service identity: other services with tuning scopes are never shown as Hermes. */
export function isHermesIdentity(name?: string | null): boolean {
  return typeof name === "string" && name.trim().toLowerCase() === HERMES_IDENTITY_NAME;
}

/** An audit entry written by Hermes, decided by who acted rather than what the action was. */
export function isHermesActor(entry: Pick<DescribableAuditEntry, "actorKind">, actorName?: string | null): boolean {
  return entry.actorKind === "service" && isHermesIdentity(actorName);
}

/** User ids an entry's wording refers to, so callers can resolve names in one query. */
export function auditNameIds(entry: DescribableAuditEntry): string[] {
  const d = obj(entry.detail);
  const ids = [d.assigneeId, obj(d.patch).ownerId, entry.targetType === "user" ? entry.targetId : undefined];
  return ids.filter((v): v is string => typeof v === "string" && v.length > 0 && v.length <= 64);
}
