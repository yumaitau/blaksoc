import { parse } from "yaml";

/**
 * Sigma support: parse + validate, evaluate against sample events (rule testing), and
 * convert to an OpenSearch query_string for Wazuh-indexer scheduled detections.
 * Covers the commonly used subset: field maps, value lists, keyword lists, the
 * contains/startswith/endswith/re/all/exists modifiers and full boolean conditions
 * including "1 of"/"all of" with wildcards.
 */

export type SigmaRule = {
  title: string;
  id: string;
  status?: string;
  description?: string;
  author?: string;
  logsource: Record<string, string>;
  detection: Record<string, unknown> & { condition: string | string[] };
  level?: "informational" | "low" | "medium" | "high" | "critical";
  tags?: string[];
  falsepositives?: string[];
};

export class SigmaError extends Error {}

const LEVELS = ["informational", "low", "medium", "high", "critical"];

export function parseSigma(yaml: string): SigmaRule {
  let doc: unknown;
  try {
    doc = parse(yaml);
  } catch (e) {
    throw new SigmaError(`YAML: ${(e as Error).message}`);
  }
  if (!doc || typeof doc !== "object") throw new SigmaError("rule must be a YAML mapping");
  const r = doc as Partial<SigmaRule>;
  if (!r.title) throw new SigmaError("missing title");
  if (!r.id || !/^[0-9a-f-]{36}$/i.test(r.id)) throw new SigmaError("id must be a UUID");
  if (!r.logsource || typeof r.logsource !== "object") throw new SigmaError("missing logsource");
  if (!r.detection || typeof r.detection !== "object" || !r.detection.condition) throw new SigmaError("detection.condition is required");
  if (r.level && !LEVELS.includes(r.level)) throw new SigmaError(`level must be one of ${LEVELS.join(", ")}`);
  const cond = Array.isArray(r.detection.condition) ? r.detection.condition : [r.detection.condition];
  for (const c of cond) validateNode(parseCondition(String(c)), r as SigmaRule);
  return r as SigmaRule;
}

/** attack.t1059.001 → T1059.001; tactic tags are ignored. */
export function attackTechniques(rule: SigmaRule): string[] {
  return [...new Set((rule.tags ?? []).map((t) => /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(t)?.[1]?.toUpperCase()).filter((t): t is string => !!t))];
}

// ---------------------------------------------------------------- field mapping

/** Sigma (Sysmon/Windows taxonomy) → Wazuh alert field paths. */
export const WAZUH_FIELD_MAP: Record<string, string> = {
  CommandLine: "data.win.eventdata.commandLine",
  Image: "data.win.eventdata.image",
  ParentImage: "data.win.eventdata.parentImage",
  ParentCommandLine: "data.win.eventdata.parentCommandLine",
  OriginalFileName: "data.win.eventdata.originalFileName",
  User: "data.win.eventdata.user",
  TargetUserName: "data.win.eventdata.targetUserName",
  SubjectUserName: "data.win.eventdata.subjectUserName",
  TargetFilename: "data.win.eventdata.targetFilename",
  TargetObject: "data.win.eventdata.targetObject",
  Hashes: "data.win.eventdata.hashes",
  DestinationIp: "data.win.eventdata.destinationIp",
  DestinationPort: "data.win.eventdata.destinationPort",
  DestinationHostname: "data.win.eventdata.destinationHostname",
  SourceIp: "data.srcip",
  QueryName: "data.win.eventdata.queryName",
  EventID: "data.win.system.eventID",
  Provider_Name: "data.win.system.providerName",
  LogonType: "data.win.eventdata.logonType",
  ScriptBlockText: "data.win.eventdata.scriptBlockText",
  ServiceName: "data.win.eventdata.serviceName",
  ImagePath: "data.win.eventdata.imagePath",
  IpAddress: "data.win.eventdata.ipAddress",
};

function lookup(event: Record<string, unknown>, field: string): unknown {
  const paths = [WAZUH_FIELD_MAP[field], field].filter(Boolean) as string[];
  for (const p of paths) {
    const v = p.split(".").reduce<unknown>((o, k) => {
      if (o == null || typeof o !== "object") return undefined;
      const rec = o as Record<string, unknown>;
      if (k in rec) return rec[k];
      const ci = Object.keys(rec).find((x) => x.toLowerCase() === k.toLowerCase());
      return ci ? rec[ci] : undefined;
    }, event);
    if (v !== undefined) return v;
  }
  return undefined;
}

// ---------------------------------------------------------------- matching

type Mods = { contains: boolean; startswith: boolean; endswith: boolean; re: boolean; all: boolean; exists: boolean; cased: boolean };

function parseKey(key: string): { field: string; mods: Mods } {
  const [field, ...m] = key.split("|");
  const has = (x: string) => m.includes(x);
  const known = ["contains", "startswith", "endswith", "re", "all", "exists", "cased", "i", "m", "s"];
  for (const x of m) if (!known.includes(x)) throw new SigmaError(`unsupported modifier |${x}`);
  return { field: field!, mods: { contains: has("contains"), startswith: has("startswith"), endswith: has("endswith"), re: has("re"), all: has("all"), exists: has("exists"), cased: has("cased") } };
}

/** Sigma wildcards: * and ? unless escaped. */
function wildcardToRegex(s: string): RegExp {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "\\" && (s[i + 1] === "*" || s[i + 1] === "?")) {
      out += `\\${s[++i]}`;
    } else if (c === "*") out += ".*";
    else if (c === "?") out += ".";
    else out += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${out}$`, "is");
}

function matchValue(actual: unknown, expected: unknown, mods: Mods): boolean {
  if (expected === null) return actual == null || actual === "";
  const values = Array.isArray(actual) ? actual : [actual];
  return values.some((a) => {
    if (a == null) return false;
    const av = String(a);
    const ev = String(expected);
    if (mods.re) return new RegExp(ev, mods.cased ? "" : "i").test(av);
    if (typeof expected === "number") return Number(a) === expected;
    const pattern = mods.contains ? `*${ev}*` : mods.startswith ? `${ev}*` : mods.endswith ? `*${ev}` : ev;
    const rx = wildcardToRegex(pattern);
    return mods.cased ? new RegExp(rx.source, "s").test(av) : rx.test(av);
  });
}

function matchMap(event: Record<string, unknown>, map: Record<string, unknown>): boolean {
  return Object.entries(map).every(([key, expected]) => {
    const { field, mods } = parseKey(key);
    const actual = lookup(event, field);
    if (mods.exists) return (actual !== undefined) === Boolean(expected);
    const list = Array.isArray(expected) ? expected : [expected];
    return mods.all ? list.every((e) => matchValue(actual, e, mods)) : list.some((e) => matchValue(actual, e, mods));
  });
}

/** Every scalar value in the event, at any depth. Field names are not searchable text. */
function leafValues(value: unknown, out: string[] = []): string[] {
  if (value == null) return out;
  if (Array.isArray(value)) value.forEach((v) => leafValues(v, out));
  else if (typeof value === "object") Object.values(value).forEach((v) => leafValues(v, out));
  else out.push(String(value));
  return out;
}

/**
 * Keyword search: a word matches when it appears in any value. Matching values one by one,
 * instead of the JSON text, keeps field names out and keeps backslashes in paths unescaped.
 */
function matchKeywords(event: Record<string, unknown>, words: unknown[]): boolean {
  const values = leafValues(event);
  return words.some((w) => {
    const rx = wildcardToRegex(`*${String(w)}*`);
    return values.some((v) => rx.test(v));
  });
}

function matchSearch(event: Record<string, unknown>, def: unknown): boolean {
  if (Array.isArray(def)) {
    if (def.every((d) => typeof d !== "object" || d === null)) return matchKeywords(event, def);
    return def.some((d) => (typeof d === "object" && d !== null ? matchMap(event, d as Record<string, unknown>) : matchKeywords(event, [d])));
  }
  if (def && typeof def === "object") return matchMap(event, def as Record<string, unknown>);
  return matchKeywords(event, [def]);
}

// ---------------------------------------------------------------- condition parser

type Tok = { t: "and" | "or" | "not" | "(" | ")" | "of" | "id" | "num" | "all" | "them"; v?: string };

function tokenize(s: string): Tok[] {
  const out: Tok[] = [];
  const re = /\s*(\(|\)|[A-Za-z0-9_*]+)/y;
  let m: RegExpExecArray | null;
  let pos = 0;
  while (pos < s.length) {
    re.lastIndex = pos;
    m = re.exec(s);
    if (!m) {
      if (/^\s*$/.test(s.slice(pos))) break;
      throw new SigmaError(`bad condition near "${s.slice(pos)}"`);
    }
    pos = re.lastIndex;
    const w = m[1]!;
    const lw = w.toLowerCase();
    if (w === "(" || w === ")") out.push({ t: w });
    else if (["and", "or", "not", "of", "all", "them"].includes(lw)) out.push({ t: lw as Tok["t"] });
    else if (/^\d+$/.test(w)) out.push({ t: "num", v: w });
    else out.push({ t: "id", v: w });
  }
  return out;
}

type Node = { k: "and" | "or"; a: Node; b: Node } | { k: "not"; a: Node } | { k: "id"; name: string } | { k: "of"; quant: "1" | "all"; pattern: string };

function parseCondition(s: string): Node {
  const toks = tokenize(s);
  let i = 0;
  const peek = () => toks[i];
  const expect = (t: Tok["t"]) => {
    if (toks[i]?.t !== t) throw new SigmaError(`expected ${t} in condition "${s}"`);
    return toks[i++]!;
  };
  const primary = (): Node => {
    const tok = peek();
    if (!tok) throw new SigmaError(`unexpected end of condition "${s}"`);
    if (tok.t === "(") {
      i++;
      const n = orExpr();
      expect(")");
      return n;
    }
    if (tok.t === "not") {
      i++;
      return { k: "not", a: primary() };
    }
    if (tok.t === "num" || tok.t === "all") {
      i++;
      expect("of");
      const target = toks[i++];
      if (!target || (target.t !== "id" && target.t !== "them")) throw new SigmaError("expected selection pattern after 'of'");
      if (tok.t === "num" && tok.v !== "1") throw new SigmaError("only '1 of' and 'all of' are supported");
      return { k: "of", quant: tok.t === "all" ? "all" : "1", pattern: target.t === "them" ? "*" : target.v! };
    }
    if (tok.t === "id") {
      i++;
      return { k: "id", name: tok.v! };
    }
    throw new SigmaError(`unexpected '${tok.t}' in condition "${s}"`);
  };
  const andExpr = (): Node => {
    let n = primary();
    while (peek()?.t === "and") {
      i++;
      n = { k: "and", a: n, b: primary() };
    }
    return n;
  };
  const orExpr = (): Node => {
    let n = andExpr();
    while (peek()?.t === "or") {
      i++;
      n = { k: "or", a: n, b: andExpr() };
    }
    return n;
  };
  const root = orExpr();
  if (i !== toks.length) throw new SigmaError(`trailing tokens in condition "${s}"`);
  return root;
}

function selectionsMatching(detection: SigmaRule["detection"], pattern: string): string[] {
  const rx = wildcardToRegex(pattern);
  return Object.keys(detection).filter((k) => k !== "condition" && k !== "timeframe" && !k.startsWith("_") && rx.test(k));
}

function validateNode(n: Node, rule: SigmaRule): void {
  if (n.k === "and" || n.k === "or") {
    validateNode(n.a, rule);
    validateNode(n.b, rule);
  } else if (n.k === "not") validateNode(n.a, rule);
  else if (n.k === "id" && !(n.name in rule.detection)) throw new SigmaError(`condition references unknown selection "${n.name}"`);
  else if (n.k === "of" && !selectionsMatching(rule.detection, n.pattern).length) throw new SigmaError(`no selections match "${n.pattern}"`);
}

function evalNode(n: Node, rule: SigmaRule, event: Record<string, unknown>): boolean {
  switch (n.k) {
    case "and": return evalNode(n.a, rule, event) && evalNode(n.b, rule, event);
    case "or": return evalNode(n.a, rule, event) || evalNode(n.b, rule, event);
    case "not": return !evalNode(n.a, rule, event);
    case "id": {
      if (!(n.name in rule.detection)) throw new SigmaError(`condition references unknown selection "${n.name}"`);
      return matchSearch(event, rule.detection[n.name]);
    }
    case "of": {
      const names = selectionsMatching(rule.detection, n.pattern);
      if (!names.length) throw new SigmaError(`no selections match "${n.pattern}"`);
      return n.quant === "all" ? names.every((x) => matchSearch(event, rule.detection[x])) : names.some((x) => matchSearch(event, rule.detection[x]));
    }
  }
}

export function matches(rule: SigmaRule, event: Record<string, unknown>): boolean {
  const conds = Array.isArray(rule.detection.condition) ? rule.detection.condition : [rule.detection.condition];
  return conds.some((c) => evalNode(parseCondition(String(c)), rule, event));
}

export function runTests(rule: SigmaRule, cases: { name: string; event: Record<string, unknown>; expect: boolean }[]) {
  const results = cases.map((c) => {
    const matched = matches(rule, c.event);
    return { name: c.name, matched, pass: matched === c.expect };
  });
  return { results, passed: results.every((r) => r.pass) };
}

// ---------------------------------------------------------------- OpenSearch conversion

const LUCENE_SPECIAL = /[+\-=&|><!(){}[\]^"~:\\/ ]/g;
const esc = (s: string) => s.replace(LUCENE_SPECIAL, "\\$&");

function luceneValue(field: string, v: unknown, mods: Mods): string {
  const f = WAZUH_FIELD_MAP[field] ?? field;
  if (mods.exists) return v ? `_exists_:${f}` : `NOT _exists_:${f}`;
  if (v === null) return `NOT _exists_:${f}`;
  if (typeof v === "number") return `${f}:${v}`;
  const s = String(v);
  if (mods.re) return `${f}:/${s.replace(/\//g, "\\/")}/`;
  // Split on Sigma wildcards, escape the literal parts.
  const body = s.split(/(?<!\\)([*?])/).map((p) => (p === "*" || p === "?" ? p : esc(p.replace(/\\([*?])/g, "$1")))).join("");
  const wrapped = mods.contains ? `*${body}*` : mods.startswith ? `${body}*` : mods.endswith ? `*${body}` : /[*?]/.test(s) ? body : `"${s.replace(/"/g, '\\"')}"`;
  return `${f}:${wrapped}`;
}

function luceneSearch(def: unknown): string {
  const kw = (w: unknown) => `"${String(w).replace(/"/g, '\\"')}"`;
  if (Array.isArray(def)) {
    if (def.every((d) => typeof d !== "object" || d === null)) return `(${def.map(kw).join(" OR ")})`;
    return `(${def.map((d) => luceneSearch(d)).join(" OR ")})`;
  }
  if (def && typeof def === "object") {
    const parts = Object.entries(def as Record<string, unknown>).map(([key, expected]) => {
      const { field, mods } = parseKey(key);
      const list = Array.isArray(expected) ? expected : [expected];
      const terms = list.map((e) => luceneValue(field, e, mods));
      return terms.length === 1 ? terms[0]! : `(${terms.join(mods.all ? " AND " : " OR ")})`;
    });
    return `(${parts.join(" AND ")})`;
  }
  return kw(def);
}

function luceneNode(n: Node, rule: SigmaRule): string {
  switch (n.k) {
    case "and": return `(${luceneNode(n.a, rule)} AND ${luceneNode(n.b, rule)})`;
    case "or": return `(${luceneNode(n.a, rule)} OR ${luceneNode(n.b, rule)})`;
    case "not": return `(NOT ${luceneNode(n.a, rule)})`;
    case "id": return luceneSearch(rule.detection[n.name]);
    case "of": {
      const names = selectionsMatching(rule.detection, n.pattern);
      return `(${names.map((x) => luceneSearch(rule.detection[x])).join(n.quant === "all" ? " AND " : " OR ")})`;
    }
  }
}

export function toOpenSearchQuery(rule: SigmaRule): string {
  const conds = Array.isArray(rule.detection.condition) ? rule.detection.condition : [rule.detection.condition];
  return conds.map((c) => luceneNode(parseCondition(String(c)), rule)).join(" OR ");
}
