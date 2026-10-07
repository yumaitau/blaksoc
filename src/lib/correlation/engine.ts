import { createHash } from "node:crypto";
import type { Severity } from "@/lib/providers/types";

/**
 * blakSOC correlation engine. Pure and deterministic, like the risk engine: the same rule and
 * events always give the same findings, and every finding lists exactly which events satisfied
 * which clause. No I/O here; the worker glue lives in src/lib/services/correlation.ts.
 */

/** A normalised event or alert. `fields` uses canonical names: event_type, user, host, src_ip, country, device, outcome, risk_score. */
export type CorrelationEvent = { id: string; at: number; fields: Record<string, unknown> };

export type Scalar = string | number | boolean;
/** Scalar: equals (strings case-insensitive). Array: any of. Array-valued fields pass when any element passes. */
export type FieldTest = Scalar | Scalar[] | { contains: string } | { gte: number } | { lte: number } | { exists: boolean } | { not: FieldTest };
/** Every field must pass. */
export type EventFilter = Record<string, FieldTest>;
/** One filter, or a list where any one may match. */
export type Match = EventFilter | EventFilter[];

export type StepAlt = {
  label: string;
  match: Match;
  /** Events needed for this alternative (default 1). The final step always takes exactly one. */
  count?: number;
  /** At least one of these fields carries a value the entity has not used before in an earlier event matching `match`. */
  novel?: { fields: string[]; minHistory?: number };
  /** At least one of these fields differs from the events chosen for an earlier step. */
  differsFrom?: { step: string; fields: string[] };
};
export type SequenceStep = { id: string; label: string; when: StepAlt[] };

/** Ordered steps, all inside `within` of the last. One finding per final event. */
export type SequenceClause = {
  type: "sequence";
  id: string;
  label: string;
  within: number;
  steps: SequenceStep[];
  /** Strictly increasing timestamps between steps (default: equal timestamps allowed). */
  strict?: boolean;
  /** No other event matching any step may fall between the chosen events. */
  contiguous?: boolean;
};
/** `threshold` matching events (or distinct values of `distinct`) inside `within`. */
export type CountClause = { type: "count"; id: string; label: string; match: Match; threshold: number; within: number; distinct?: string };
/** A trigger event not followed by a matching event inside `within`. Only decided once the window has closed. */
export type AbsenceClause = {
  type: "absence";
  id: string;
  label: string;
  within: number;
  trigger: { label: string; match: Match };
  missing: { label: string; match: Match; sameFields?: string[] };
};
/** Sum of `field` (default risk_score) over matching events inside `within` reaches `threshold`. */
export type RiskClause = { type: "risk"; id: string; label: string; within: number; threshold: number; match?: Match; field?: string };
export type Clause = SequenceClause | CountClause | AbsenceClause | RiskClause;

/** Corroborating evidence for the same entity. No `within` means anywhere in the evaluated events. */
export type RequireClause = { id: string; label: string; match: Match; within?: number; min?: number };

export type CorrelationRule = {
  id: string;
  /** Bump when the logic changes. Findings record the version that produced them. */
  version: number;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  techniques: string[];
  /** `source`: runs inside a provider over its raw records. `alerts`: the worker runs it over stored alerts. */
  stage: "source" | "alerts";
  enabledByDefault: boolean;
  /** Entity fields every event must carry; findings are per entity. */
  groupBy: string[];
  clause: Clause;
  require?: RequireClause[];
  /** Drop later findings for the same entity inside this span. Default: `within` for count and risk, 0 otherwise. */
  suppressFor?: number;
  /** alerts.raw.eventType of the correlated alert. */
  eventType: string;
};

export type EventRef = { id: string; at: string; summary: string };
export type ClauseMatch = { clause: string; label: string; events: EventRef[]; note?: string };

export type CorrelationFinding = {
  ruleId: string;
  ruleVersion: number;
  /** Stable across runs: rule, entity and anchor event. */
  dedupeKey: string;
  entity: Record<string, string>;
  anchorId: string;
  firstAt: number;
  lastAt: number;
  matches: ClauseMatch[];
  explanation: string[];
  /** Every event id that contributed, sorted. */
  eventIds: string[];
};

// ---------------------------------------------------------------- matching

function get(e: CorrelationEvent, path: string): unknown {
  if (path in e.fields) return e.fields[path];
  let cur: unknown = e.fields;
  for (const part of path.split(".")) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

function norm(v: unknown): string {
  return v == null ? "" : String(v).trim().toLowerCase();
}

function present(v: unknown): boolean {
  return v != null && v !== "" && !(Array.isArray(v) && v.length === 0);
}

function scalarEq(v: unknown, s: Scalar): boolean {
  if (typeof s === "number") return Number(v) === s;
  if (typeof s === "boolean") return v === s || norm(v) === String(s);
  return norm(v) === s.toLowerCase();
}

function testValue(v: unknown, t: FieldTest): boolean {
  if (t !== null && typeof t === "object" && !Array.isArray(t)) {
    if ("not" in t) return !testValue(v, t.not);
    if ("exists" in t) return present(v) === t.exists;
    if (Array.isArray(v)) return v.some((x) => testValue(x, t));
    if ("contains" in t) return norm(v).includes(t.contains.toLowerCase());
    const n = Number(v);
    if (v == null || v === "" || !Number.isFinite(n)) return false;
    if ("gte" in t) return n >= t.gte;
    return n <= t.lte;
  }
  if (Array.isArray(v)) return v.some((x) => testValue(x, t));
  if (v == null) return false;
  return Array.isArray(t) ? t.some((s) => scalarEq(v, s)) : scalarEq(v, t);
}

export function matches(e: CorrelationEvent, m: Match): boolean {
  const pass = (f: EventFilter) => Object.entries(f).every(([k, t]) => testValue(get(e, k), t));
  return Array.isArray(m) ? m.some(pass) : pass(m);
}

// ---------------------------------------------------------------- helpers

const iso = (ms: number) => new Date(ms).toISOString();

function ref(e: CorrelationEvent): EventRef {
  const summary = get(e, "summary") ?? get(e, "title") ?? get(e, "event_type") ?? "event";
  return { id: e.id, at: iso(e.at), summary: String(summary) };
}

export function duration(ms: number): string {
  if (ms % 3_600_000 === 0) return `${ms / 3_600_000}h`;
  if (ms % 60_000 === 0) return `${ms / 60_000}m`;
  return `${Math.round(ms / 1000)}s`;
}

function byTime(a: CorrelationEvent, b: CorrelationEvent) {
  return a.at - b.at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/** Dedupe by id (first wins), drop events without a usable time, sort by time then id. */
function prepare(events: CorrelationEvent[]): CorrelationEvent[] {
  const seen = new Set<string>();
  const out: CorrelationEvent[] = [];
  for (const e of events) {
    if (!e.id || !Number.isFinite(e.at) || seen.has(e.id)) continue;
    seen.add(e.id);
    out.push(e);
  }
  return out.sort(byTime);
}

function entityOf(rule: CorrelationRule, e: CorrelationEvent): Record<string, string> | null {
  const out: Record<string, string> = {};
  for (const f of rule.groupBy) {
    const v = norm(get(e, f));
    if (!v) return null;
    out[f] = v;
  }
  return out;
}

const entityKey = (entity: Record<string, string>) => Object.entries(entity).map(([k, v]) => `${k}=${v}`).join("|");

// ---------------------------------------------------------------- clauses

type Candidate = { anchorId: string; firstAt: number; lastAt: number; matches: ClauseMatch[]; summary: string };

/** Node budget per final event, so a pathological entity cannot stall the worker. */
const SEARCH_BUDGET = 20_000;

function sequenceCandidates(c: SequenceClause, all: CorrelationEvent[]): Candidate[] {
  const relevant = (e: CorrelationEvent) => c.steps.some((s) => s.when.some((a) => matches(e, a.match)));
  const pool = c.contiguous ? all.filter(relevant) : all;
  const position = new Map(all.map((e, i) => [e.id, i]));
  const last = c.steps.length - 1;
  const out: Candidate[] = [];

  const novelSeen = new Map<StepAlt, Map<string, boolean>>();
  const novel = (e: CorrelationEvent, alt: StepAlt) => {
    if (!alt.novel) return true;
    const memo = novelSeen.get(alt) ?? new Map<string, boolean>();
    novelSeen.set(alt, memo);
    const hit = memo.get(e.id);
    if (hit !== undefined) return hit;
    const spec = alt.novel;
    const before = all.slice(0, position.get(e.id)).filter((h) => matches(h, alt.match));
    const result = before.length >= (spec.minHistory ?? 1) && spec.fields.some((f) => {
      const v = norm(get(e, f));
      return !!v && !before.some((h) => norm(get(h, f)) === v);
    });
    memo.set(e.id, result);
    return result;
  };
  const differs = (e: CorrelationEvent, alt: StepAlt, chosen: Map<string, CorrelationEvent[]>) => {
    if (!alt.differsFrom) return true;
    const prior = chosen.get(alt.differsFrom.step) ?? [];
    return alt.differsFrom.fields.some((f) => {
      const v = norm(get(e, f));
      const others = prior.map((p) => norm(get(p, f)));
      return !!v && others.length > 0 && others.every((o) => !!o && o !== v);
    });
  };
  const ok = (e: CorrelationEvent, alt: StepAlt, chosen: Map<string, CorrelationEvent[]>) => matches(e, alt.match) && novel(e, alt) && differs(e, alt, chosen);

  /** First index whose time is >= at (or > at when strict). */
  const lowerBound = (at: number, strict: boolean) => {
    let [a, b] = [0, pool.length];
    while (a < b) {
      const m = (a + b) >> 1;
      if (strict ? pool[m]!.at <= at : pool[m]!.at < at) a = m + 1;
      else b = m;
    }
    return a;
  };

  for (let t = 0; t < pool.length; t++) {
    const term = pool[t]!;
    const lo = term.at - c.within;
    // Events sharing the final event's timestamp may sit after it in id order; ties are unordered unless strict.
    const hi = c.contiguous ? t - 1 : lowerBound(term.at, true) - 1;
    for (const termAlt of c.steps[last]!.when) {
      if (!matches(term, termAlt.match) || !novel(term, termAlt)) continue;
      let budget = SEARCH_BUDGET;
      const picks: { alt: StepAlt; idx: number[] }[] = [];
      const chosen = new Map<string, CorrelationEvent[]>();
      const used = new Set<number>([t]);
      const free = (i: number) => !used.has(i);

      const search = (k: number, from: number, prevAt: number): boolean => {
        if (--budget < 0) return false;
        if (k === last) {
          if (c.strict && !(term.at > prevAt)) return false;
          if (c.contiguous && from !== t) return false;
          return differs(term, termAlt, chosen);
        }
        const step = c.steps[k]!;
        const begin = c.contiguous ? from : Math.max(lowerBound(prevAt, !!c.strict), lowerBound(lo, false));
        for (const alt of step.when) {
          const need = Math.max(1, alt.count ?? 1);
          for (let p = begin; p <= hi; p++) {
            if (c.contiguous && k > 0 && p !== from) break;
            const first = pool[p]!;
            if (!free(p) || first.at < lo || (c.strict && !(first.at > prevAt)) || !ok(first, alt, chosen)) continue;
            const idx = [p];
            for (let q = p + 1; q <= hi && idx.length < need; q++) {
              if (free(q) && ok(pool[q]!, alt, chosen)) idx.push(q);
              else if (c.contiguous) break;
            }
            // Fewer matches remain from later starts, unless contiguity is what failed.
            if (idx.length < need) {
              if (c.contiguous) continue;
              break;
            }
            picks[k] = { alt, idx };
            chosen.set(step.id, idx.map((i) => pool[i]!));
            idx.forEach((i) => used.add(i));
            if (search(k + 1, idx.at(-1)! + 1, pool[idx.at(-1)!]!.at)) return true;
            idx.forEach((i) => used.delete(i));
            chosen.delete(step.id);
            if (budget < 0) return false;
          }
        }
        return false;
      };

      if (!search(0, 0, Number.NEGATIVE_INFINITY)) continue;
      // Report every event that satisfies a step up to the next step, not just the minimum the step needed.
      if (!c.contiguous) {
        for (let k = 0; k < last; k++) {
          const pick = picks[k]!;
          const until = k + 1 < last ? pool[picks[k + 1]!.idx[0]!]!.at : term.at;
          for (let q = pick.idx.at(-1)! + 1; q <= hi && pool[q]!.at <= until; q++) {
            if (free(q) && ok(pool[q]!, pick.alt, chosen)) {
              pick.idx.push(q);
              used.add(q);
            }
          }
        }
      }
      const stepMatches: ClauseMatch[] = c.steps.map((s, k) => {
        const alt = k === last ? termAlt : picks[k]!.alt;
        const events = k === last ? [term] : picks[k]!.idx.map((i) => pool[i]!);
        return { clause: `${c.id}.${s.id}`, label: `${s.label}: ${alt.label}`, events: events.map(ref) };
      });
      out.push({
        anchorId: term.id,
        firstAt: pool[picks[0]!.idx[0]!]!.at,
        lastAt: term.at,
        matches: stepMatches,
        summary: `${c.steps.length} steps in order within ${duration(c.within)}`,
      });
      break;
    }
  }
  return out;
}

function windowCandidates(
  c: CountClause | RiskClause,
  all: CorrelationEvent[],
  measure: (w: CorrelationEvent[]) => { value: number; note: string; events: CorrelationEvent[] },
): Candidate[] {
  const m = c.match ? all.filter((e) => matches(e, c.match!)) : all;
  const out: Candidate[] = [];
  let start = 0;
  for (let i = 0; i < m.length; i++) {
    const e = m[i]!;
    while (m[start]!.at < e.at - c.within) start++;
    const r = measure(m.slice(start, i + 1));
    if (r.value < c.threshold) continue;
    out.push({ anchorId: e.id, firstAt: r.events[0]?.at ?? e.at, lastAt: e.at, matches: [{ clause: c.id, label: c.label, events: r.events.map(ref), note: r.note }], summary: r.note });
  }
  return out;
}

function countCandidates(c: CountClause, all: CorrelationEvent[]): Candidate[] {
  return windowCandidates(c, all, (w) => {
    if (!c.distinct) return { value: w.length, note: `${w.length} events within ${duration(c.within)} (threshold ${c.threshold})`, events: w };
    const values = [...new Set(w.map((e) => norm(get(e, c.distinct!))).filter(Boolean))].sort();
    return { value: values.length, note: `${values.length} distinct ${c.distinct} within ${duration(c.within)} (threshold ${c.threshold}): ${values.join(", ")}`, events: w };
  });
}

function riskCandidates(c: RiskClause, all: CorrelationEvent[]): Candidate[] {
  const field = c.field ?? "risk_score";
  const points = (e: CorrelationEvent) => Math.max(0, Number(get(e, field)) || 0);
  return windowCandidates(c, all, (w) => {
    const scored = w.filter((e) => points(e) > 0);
    const total = scored.reduce((s, e) => s + points(e), 0);
    return { value: total, note: `${field} total ${total} within ${duration(c.within)} (threshold ${c.threshold}): ${scored.map((e) => `${e.id}=${points(e)}`).join(", ")}`, events: scored };
  });
}

function absenceCandidates(c: AbsenceClause, all: CorrelationEvent[], now: number | undefined): Candidate[] {
  if (now === undefined) return [];
  const out: Candidate[] = [];
  for (const a of all) {
    if (!matches(a, c.trigger.match)) continue;
    const end = a.at + c.within;
    if (now < end) continue; // still open: B could yet arrive
    const followed = all.some(
      (b) => b.id !== a.id && b.at > a.at && b.at <= end && matches(b, c.missing.match) && (c.missing.sameFields ?? []).every((f) => norm(get(a, f)) === norm(get(b, f))),
    );
    if (followed) continue;
    out.push({
      anchorId: a.id,
      firstAt: a.at,
      lastAt: end,
      matches: [
        { clause: `${c.id}.trigger`, label: c.trigger.label, events: [ref(a)] },
        { clause: `${c.id}.missing`, label: c.missing.label, events: [], note: `no matching event between ${iso(a.at)} and ${iso(end)}` },
      ],
      summary: `${c.trigger.label} not followed by ${c.missing.label} within ${duration(c.within)}`,
    });
  }
  return out;
}

function candidates(c: Clause, events: CorrelationEvent[], now: number | undefined): Candidate[] {
  switch (c.type) {
    case "sequence": return sequenceCandidates(c, events);
    case "count": return countCandidates(c, events);
    case "risk": return riskCandidates(c, events);
    case "absence": return absenceCandidates(c, events, now);
  }
}

// ---------------------------------------------------------------- evaluation

export function dedupeKeyFor(ruleId: string, entity: Record<string, string>, anchorId: string): string {
  const h = createHash("sha256").update(`${ruleId}\n${entityKey(entity)}\n${anchorId}`).digest("hex").slice(0, 32);
  return `corr:${ruleId}:${h}`;
}

/**
 * Evaluate one rule over events. `now` decides whether absence windows have closed;
 * without it absence clauses never fire.
 */
export function evaluateRule(rule: CorrelationRule, events: CorrelationEvent[], now?: number): CorrelationFinding[] {
  const groups = new Map<string, { entity: Record<string, string>; events: CorrelationEvent[] }>();
  for (const e of prepare(events)) {
    const entity = entityOf(rule, e);
    if (!entity) continue;
    const key = entityKey(entity);
    const g = groups.get(key) ?? { entity, events: [] };
    g.events.push(e);
    groups.set(key, g);
  }
  const suppress = rule.suppressFor ?? (rule.clause.type === "count" || rule.clause.type === "risk" ? rule.clause.within : 0);
  const findings: CorrelationFinding[] = [];

  for (const key of [...groups.keys()].sort()) {
    const { entity, events: list } = groups.get(key)!;
    let lastEmitted = Number.NEGATIVE_INFINITY;
    for (const cand of candidates(rule.clause, list, now)) {
      const extra: ClauseMatch[] = [];
      let satisfied = true;
      for (const r of rule.require ?? []) {
        const hits = list.filter((e) => matches(e, r.match) && (r.within === undefined || (e.at >= cand.firstAt - r.within && e.at <= cand.lastAt + r.within)));
        if (hits.length < (r.min ?? 1)) {
          satisfied = false;
          break;
        }
        extra.push({ clause: r.id, label: r.label, events: hits.map(ref) });
      }
      if (!satisfied) continue;
      if (suppress > 0 && cand.lastAt - lastEmitted < suppress) continue;
      lastEmitted = cand.lastAt;
      const all = [...cand.matches, ...extra];
      const who = Object.entries(entity).map(([k, v]) => `${k} ${v}`).join(", ");
      findings.push({
        ruleId: rule.id,
        ruleVersion: rule.version,
        dedupeKey: dedupeKeyFor(rule.id, entity, cand.anchorId),
        entity,
        anchorId: cand.anchorId,
        firstAt: cand.firstAt,
        lastAt: cand.lastAt,
        matches: all,
        explanation: [
          `${rule.title} for ${who}: ${cand.summary}.`,
          ...all.map((m) => `${m.label}: ${m.events.length ? m.events.map((e) => `${e.summary} at ${e.at} [${e.id}]`).join("; ") : "none"}${m.note ? ` (${m.note})` : ""}`),
        ],
        eventIds: [...new Set(all.flatMap((m) => m.events.map((e) => e.id)))].sort(),
      });
    }
  }
  return findings;
}

/** All rules over the same events, ordered by time then dedupe key. */
export function evaluateRules(rules: CorrelationRule[], events: CorrelationEvent[], now?: number): CorrelationFinding[] {
  return rules.flatMap((r) => evaluateRule(r, events, now)).sort((a, b) => a.lastAt - b.lastAt || (a.dedupeKey < b.dedupeKey ? -1 : 1));
}

/** Structural checks for a rule definition. Empty means valid. */
export function validateRule(rule: CorrelationRule): string[] {
  const errors: string[] = [];
  const c = rule.clause;
  if (!/^[a-z0-9][a-z0-9-]*$/.test(rule.id)) errors.push("id must be lowercase kebab-case");
  if (!Number.isInteger(rule.version) || rule.version < 1) errors.push("version must be a positive integer");
  if (!rule.groupBy.length) errors.push("groupBy needs at least one entity field");
  if (!(c.within > 0)) errors.push("within must be positive");
  if (c.type === "sequence") {
    if (c.steps.length < 2) errors.push("a sequence needs at least two steps");
    const ids = new Set<string>();
    c.steps.forEach((s, k) => {
      if (ids.has(s.id)) errors.push(`duplicate step id ${s.id}`);
      if (!s.when.length) errors.push(`step ${s.id} has no alternatives`);
      for (const a of s.when) {
        if (a.count !== undefined && (!Number.isInteger(a.count) || a.count < 1)) errors.push(`step ${s.id}: count must be a positive integer`);
        if (k === c.steps.length - 1 && (a.count ?? 1) !== 1) errors.push(`final step ${s.id} must take exactly one event`);
        if (a.differsFrom && !ids.has(a.differsFrom.step)) errors.push(`step ${s.id}: differsFrom must name an earlier step`);
      }
      ids.add(s.id);
    });
  }
  if ((c.type === "count" || c.type === "risk") && !(c.threshold > 0)) errors.push("threshold must be positive");
  for (const r of rule.require ?? []) if (r.within !== undefined && !(r.within > 0)) errors.push(`require ${r.id}: within must be positive`);
  return errors;
}
