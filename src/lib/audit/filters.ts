/**
 * Audit trail filters as they travel in the URL. Pure, so the page and its CSV export
 * read the same query string the same way.
 */

export const AUDIT_ACTOR_KINDS = ["user", "system", "playbook", "ai", "service"] as const;
export type AuditActorKind = (typeof AUDIT_ACTOR_KINDS)[number];
export const AUDIT_PERIODS = [1, 7, 30, 90, 365] as const;

export type AuditFilters = {
  tenantId?: string;
  /** Action key prefix, e.g. "rbac." */
  action?: string;
  /** Used when neither from nor to is set. */
  sinceDays: number;
  /** Inclusive calendar days (YYYY-MM-DD, Australia/Sydney). Either one replaces sinceDays. */
  from?: string;
  to?: string;
  /** Actor id, or part of a user's name or email, or a service identity's name. */
  actor?: string;
  actorKind?: AuditActorKind;
  targetType?: string;
  targetId?: string;
  /** Free text over action, target type and target id. */
  q?: string;
  /** Cursor: entries with a smaller id (older). */
  before?: number;
};

type SearchParams = Record<string, string | string[] | undefined>;

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim() || undefined;
const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** A real calendar day in YYYY-MM-DD form, or undefined. */
export function auditDay(v: string | undefined): string | undefined {
  const m = v ? DAY.exec(v) : null;
  if (!m) return undefined;
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  return d.getUTCFullYear() >= 2000 && d.getUTCFullYear() <= 9999 && d.toISOString().slice(0, 10) === v ? v : undefined;
}

/**
 * Validated, length-limited filters. A tenant the caller cannot read the audit trail of is
 * dropped rather than trusted; the service checks scope again.
 */
export function parseAuditFilters(sp: SearchParams, readableTenantIds: readonly string[]): AuditFilters {
  const days = Number(first(sp.days));
  const tenant = first(sp.tenant);
  const kind = first(sp.actorKind);
  const targetType = first(sp.targetType)?.slice(0, 40);
  const before = Number(first(sp.before));
  let from = auditDay(first(sp.from));
  let to = auditDay(first(sp.to));
  if (from && to && from > to) [from, to] = [to, from];
  return {
    tenantId: tenant && readableTenantIds.includes(tenant) ? tenant : undefined,
    action: first(sp.action)?.slice(0, 60),
    sinceDays: (AUDIT_PERIODS as readonly number[]).includes(days) ? days : 30,
    from,
    to,
    actor: first(sp.actor)?.slice(0, 120),
    actorKind: (AUDIT_ACTOR_KINDS as readonly string[]).includes(kind ?? "") ? (kind as AuditActorKind) : undefined,
    targetType: targetType && /^[a-z0-9_.-]+$/i.test(targetType) ? targetType : undefined,
    targetId: first(sp.targetId)?.slice(0, 200),
    q: first(sp.q)?.slice(0, 100),
    before: Number.isSafeInteger(before) && before > 0 ? before : undefined,
  };
}

/** Query string for these filters (without the cursor unless asked), for shareable links. */
export function auditQuery(f: AuditFilters, opts: { before?: number } = {}): string {
  const qs = new URLSearchParams();
  const set = (k: string, v: string | number | undefined) => {
    if (v !== undefined && v !== "") qs.set(k, String(v));
  };
  set("tenant", f.tenantId);
  set("action", f.action);
  if (!f.from && !f.to && f.sinceDays !== 30) set("days", f.sinceDays);
  set("from", f.from);
  set("to", f.to);
  set("actor", f.actor);
  set("actorKind", f.actorKind);
  set("targetType", f.targetType);
  set("targetId", f.targetId);
  set("q", f.q);
  set("before", opts.before);
  return qs.toString();
}
