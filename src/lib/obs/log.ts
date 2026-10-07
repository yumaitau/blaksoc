import { obsContext } from "./context";

/**
 * Structured JSON logger for web and worker. One line per entry on stdout with level, time, msg,
 * the correlation fields of the current request or job, and redacted fields. Secrets and raw event
 * payloads never reach a log line: keys are matched by name and strings are scrubbed for tokens.
 */
export type Level = "debug" | "info" | "warn" | "error";
export type Fields = Record<string, unknown>;
export type Logger = { [L in Level]: (msg: string, fields?: Fields) => void } & { child: (bindings: Fields) => Logger };

const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

// Normalised key (lower case, letters and digits only) that names a credential: contains one of these
// words, or ends in "token" (accesstoken, idtoken; not "tokenizer").
const SECRET_WORD = /password|passwd|passphrase|secret|authorization|cookie|apikey|privatekey|encryptionkey|credential|signature/;
const SECRET_EXACT = new Set(["key", "dsn", "otp", "totp", "connectionstring"]);
// Raw provider events and alert bodies: tenant telemetry, never operational data.
const PAYLOAD_KEY = new Set(["raw", "rawevent", "rawlog", "rawpayload", "payload", "body", "requestbody", "responsebody", "line", "lines", "alert", "alerts", "finding", "sourceevent", "notification"]);

const MAX_STRING = 2_000;
const MAX_DEPTH = 6;
const MAX_ITEMS = 50;

const SCRUB: [RegExp, string][] = [
  // Drizzle query errors append bound parameters, which can hold alert JSON or encrypted config.
  [/(\bparams: )[\s\S]*$/, "$1[redacted]"],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]"],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, "[jwt]"],
  [/([a-z][a-z0-9+.-]*:\/\/)([^\s:/@]+):([^\s@/]+)@/gi, "$1$2:[redacted]@"],
  [/("[^"]*(?:password|secret|token|api_?key|authorization|cookie)[^"]*"\s*:\s*)"[^"]*"/gi, '$1"[redacted]"'],
  [/\b((?:access_|refresh_|id_)?token|api[_-]?key|client_secret|password|passwd|secret|sig|signature)=([^&\s"',;]+)/gi, "$1=[redacted]"],
  [/([?&]code=)[^&\s"']+/gi, "$1[redacted]"],
];

export function scrub(s: string): string {
  let out = s.length > MAX_STRING ? `${s.slice(0, MAX_STRING)}…` : s;
  for (const [re, to] of SCRUB) out = out.replace(re, to);
  return out;
}

function serializeError(err: Error, depth: number, seen: WeakSet<object>): Fields {
  const out: Fields = { type: err.name, message: scrub(err.message) };
  const code = (err as { code?: unknown }).code;
  if (typeof code === "string" || typeof code === "number") out.code = code;
  if (err.stack) out.stack = scrub(err.stack);
  if (err.cause != null && depth < MAX_DEPTH) out.cause = redact(err.cause, depth + 1, seen);
  return out;
}

/** Deep copy with credentials replaced and raw payloads dropped. Exported for tests and callers that build their own lines. */
export function redact(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (value == null || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") return scrub(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value !== "object") return typeof value === "function" ? "[function]" : String(value);
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString();
  if (value instanceof Error) return serializeError(value, depth, seen);
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return "[binary]";
  if (seen.has(value)) return "[circular]";
  if (depth >= MAX_DEPTH) return "[depth]";
  seen.add(value);
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ITEMS).map((v) => redact(v, depth + 1, seen));
    if (value.length > MAX_ITEMS) items.push(`[+${value.length - MAX_ITEMS} more]`);
    return items;
  }
  const entries: [string, unknown][] =
    value instanceof Headers || value instanceof Map ? [...(value as Map<string, unknown>).entries()].map(([k, v]) => [String(k), v]) : Object.entries(value);
  const out: Fields = {};
  for (const [k, v] of entries) {
    const norm = k.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (SECRET_WORD.test(norm) || norm.endsWith("token") || SECRET_EXACT.has(norm)) out[k] = "[redacted]";
    else if (PAYLOAD_KEY.has(norm)) out[k] = "[omitted]";
    else out[k] = redact(v, depth + 1, seen);
  }
  return out;
}

type Sink = (line: string, level: Level) => void;
const g = globalThis as unknown as { __blaksocLogSink?: Sink; __blaksocService?: string };

/** Names the process on every line ("web" unless the worker says otherwise). */
export function setLogService(name: string) {
  g.__blaksocService = name;
}

/** Tests capture lines here; production writes one line per entry to stdout. */
export function setLogSink(sink: Sink | undefined) {
  g.__blaksocLogSink = sink;
}

function threshold(): number {
  const configured = process.env.LOG_LEVEL as Level | undefined;
  if (configured && configured in ORDER) return ORDER[configured];
  return process.env.NODE_ENV === "test" ? ORDER.warn : ORDER.info;
}

function format(entry: Fields): string {
  if (process.env.LOG_FORMAT !== "pretty") return JSON.stringify(entry);
  const { time, level, msg, ...rest } = entry;
  const tail = Object.entries(rest).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`);
  return [time, String(level).toUpperCase().padEnd(5), msg, ...tail].join(" ");
}

function emit(level: Level, bindings: Fields, msg: string, fields?: Fields) {
  if (ORDER[level] < threshold()) return;
  const entry: Fields = { time: new Date().toISOString(), level, msg: scrub(msg), service: g.__blaksocService ?? "web" };
  for (const [k, v] of Object.entries(obsContext())) if (v != null) entry[k] = v;
  const extra = redact({ ...bindings, ...fields }) as Fields;
  for (const [k, v] of Object.entries(extra)) if (v !== undefined && !["time", "level", "msg", "service"].includes(k)) entry[k] = v;
  let line: string;
  try {
    line = format(entry);
  } catch {
    line = JSON.stringify({ time: entry.time, level, msg: entry.msg, logError: "unserialisable fields" });
  }
  if (g.__blaksocLogSink) g.__blaksocLogSink(line, level);
  else process.stdout.write(`${line}\n`);
}

function make(bindings: Fields): Logger {
  return {
    debug: (msg, fields) => emit("debug", bindings, msg, fields),
    info: (msg, fields) => emit("info", bindings, msg, fields),
    warn: (msg, fields) => emit("warn", bindings, msg, fields),
    error: (msg, fields) => emit("error", bindings, msg, fields),
    child: (more) => make({ ...bindings, ...more }),
  };
}

/** Process-wide logger. `service` tells web and worker lines apart in a shared log store. */
export const logger: Logger = make({});
