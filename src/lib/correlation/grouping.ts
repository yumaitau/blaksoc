/**
 * Automatic incident grouping. Pure and deterministic: the same alerts (in any order) give the same
 * plans. Two alerts are related when they share an entity (user or asset) inside the window and share
 * an ATT&CK technique or tactic, or when one is a correlated alert built from the other. Related alerts
 * form connected groups; a group either joins the open incident one of its alerts is already in, or
 * becomes a new incident once it holds `minAlerts` alerts.
 */

export type GroupableAlert = {
  id: string;
  occurredAt: number;
  userName: string | null;
  assetId: string | null;
  techniques: string[];
  /** Open incident the alert is already in; null for a candidate. */
  incidentId: string | null;
  /** For correlated alerts: the alert ids that produced it. */
  relatedIds?: string[];
};

export type GroupEdge = { a: string; b: string; entities: string[]; techniques: string[]; tactics: string[]; correlated: boolean };

export type GroupReason = {
  entities: string[];
  techniques: string[];
  tactics: string[];
  windowMs: number;
  firstAt: string;
  lastAt: string;
  /** The edges that joined the group (a spanning set, plus correlation links), at most MAX_REASON_EDGES. */
  edges: GroupEdge[];
  /** All joining edges, when more than the ones kept. */
  edgeCount: number;
  summary: string;
};

/**
 * Edges kept on a reason. The reason is stored on every linked alert, so a scan of thousands of alerts on one
 * host must not carry thousands of edges each.
 */
export const MAX_REASON_EDGES = 50;

export type GroupPlan = {
  /** Deterministic key for a new incident (`grp:` + earliest alert id); null when joining an existing incident. */
  groupingKey: string | null;
  incidentId: string | null;
  /** Candidate alerts to link, in time order. */
  alertIds: string[];
  reason: GroupReason;
};

export type GroupingOptions = {
  windowMs: number;
  /** ATT&CK tactics per technique id (sub-techniques fall back to their parent). */
  tactics: Record<string, string[]>;
  minAlerts?: number;
};

const order = (a: GroupableAlert, b: GroupableAlert) => a.occurredAt - b.occurredAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

function entitiesOf(a: GroupableAlert): string[] {
  const out: string[] = [];
  if (a.userName?.trim()) out.push(`user:${a.userName.trim().toLowerCase()}`);
  if (a.assetId) out.push(`asset:${a.assetId}`);
  return out;
}

function techniquesOf(a: GroupableAlert): string[] {
  const out = new Set<string>();
  for (const t of a.techniques) {
    const id = t.trim().toUpperCase();
    if (!/^T\d{4}(\.\d{3})?$/.test(id)) continue;
    out.add(id.split(".")[0]!);
  }
  return [...out];
}

function tacticsOf(a: GroupableAlert, map: Record<string, string[]>): string[] {
  const out = new Set<string>();
  for (const t of a.techniques) {
    const id = t.trim().toUpperCase();
    for (const tac of map[id] ?? map[id.split(".")[0]!] ?? []) out.add(tac);
  }
  return [...out];
}

const shared = (x: string[], y: string[]) => x.filter((v) => y.includes(v)).sort();

export function planGroups(input: GroupableAlert[], opts: GroupingOptions): GroupPlan[] {
  const minAlerts = opts.minAlerts ?? 2;
  const byId = new Map<string, GroupableAlert>();
  for (const a of input) if (!byId.has(a.id)) byId.set(a.id, a);
  const alerts = [...byId.values()].sort(order);
  const info = alerts.map((a) => ({ entities: entitiesOf(a), techniques: techniquesOf(a), tactics: tacticsOf(a, opts.tactics), related: new Set(a.relatedIds ?? []) }));

  const parent = alerts.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i]!)));
  const union = (i: number, j: number) => {
    const [a, b] = [find(i), find(j)];
    if (a !== b) parent[Math.max(a, b)] = Math.min(a, b);
  };

  const edges: { i: number; j: number; edge: GroupEdge }[] = [];
  const consider = (i: number, j: number) => {
    const [a, b] = [alerts[i]!, alerts[j]!];
    const correlated = info[i]!.related.has(b.id) || info[j]!.related.has(a.id);
    // Already connected: the pair changes no group. Recording every related pair in a window was quadratic
    // (gigabytes for one host's benchmark scan). Correlation links are few and always kept as evidence.
    if (!correlated && find(i) === find(j)) return;
    const entities = shared(info[i]!.entities, info[j]!.entities);
    if (!entities.length) return;
    const techniques = shared(info[i]!.techniques, info[j]!.techniques);
    const tactics = shared(info[i]!.tactics, info[j]!.tactics);
    if (!correlated && !techniques.length && !tactics.length) return;
    // Two alerts already in incidents stay where analysts put them.
    if (a.incidentId && b.incidentId) return;
    edges.push({ i, j, edge: { a: a.id, b: b.id, entities, techniques, tactics, correlated } });
    union(i, j);
  };
  const index = new Map(alerts.map((a, i) => [a.id, i]));
  for (let i = 0; i < alerts.length; i++) {
    for (let j = i + 1; j < alerts.length && alerts[j]!.occurredAt - alerts[i]!.occurredAt <= opts.windowMs; j++) consider(i, j);
  }
  // Correlation links hold past the window.
  for (let i = 0; i < alerts.length; i++) {
    for (const id of info[i]!.related) {
      const j = index.get(id);
      if (j === undefined || j === i) continue;
      const [x, y] = i < j ? [i, j] : [j, i];
      if (alerts[y]!.occurredAt - alerts[x]!.occurredAt > opts.windowMs) consider(x, y);
    }
  }
  edges.sort((p, q) => p.i - q.i || p.j - q.j);

  const groups = new Map<number, number[]>();
  alerts.forEach((_, i) => {
    const root = find(i);
    const members = groups.get(root);
    if (members) members.push(i);
    else groups.set(root, [i]);
  });

  const plans: GroupPlan[] = [];
  for (const root of [...groups.keys()].sort((x, y) => x - y)) {
    const members = groups.get(root)!;
    const candidates = members.filter((i) => !alerts[i]!.incidentId);
    if (!candidates.length) continue;
    const anchored = members.find((i) => alerts[i]!.incidentId);
    if (anchored === undefined && members.length < minAlerts) continue;
    const memberSet = new Set(members);
    const groupEdges = edges.filter((e) => memberSet.has(e.i)).map((e) => e.edge);
    const collect = (k: "entities" | "techniques" | "tactics") => [...new Set(groupEdges.flatMap((e) => e[k]))].sort();
    const first = alerts[members[0]!]!;
    const last = alerts[members.at(-1)!]!;
    const reason: GroupReason = {
      entities: collect("entities"),
      techniques: collect("techniques"),
      tactics: collect("tactics"),
      windowMs: opts.windowMs,
      firstAt: new Date(first.occurredAt).toISOString(),
      lastAt: new Date(last.occurredAt).toISOString(),
      edges: groupEdges.slice(0, MAX_REASON_EDGES),
      edgeCount: groupEdges.length,
      summary: "",
    };
    const common = [...reason.tactics, ...reason.techniques];
    reason.summary = [
      `same ${reason.entities.join(", ")}`,
      `within ${Math.round(opts.windowMs / 3_600_000)}h`,
      common.length ? `shared ATT&CK ${common.join(", ")}` : null,
      groupEdges.some((e) => e.correlated) ? "linked by a correlation finding" : null,
    ].filter(Boolean).join("; ");
    plans.push({
      groupingKey: anchored === undefined ? `grp:${first.id}` : null,
      incidentId: anchored === undefined ? null : alerts[anchored]!.incidentId,
      alertIds: candidates.map((i) => alerts[i]!.id),
      reason,
    });
  }
  return plans;
}
