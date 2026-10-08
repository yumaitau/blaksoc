import { DrizzleQueryError } from "drizzle-orm";

/**
 * Plain-language messages for errors a server action may throw. Only the error's kind and schema
 * facts (field paths, constraint names, a configured host name) reach the message: never submitted
 * values, SQL, bound parameters, stack traces or another tenant's data.
 *
 * Returns null for anything unrecognised; the caller then shows a generic message with a reference.
 * `log` is false for input mistakes the user can fix themselves.
 */
export type ExplainedError = { message: string; log: boolean };

export const CONCURRENT_CHANGE = "Another change was being saved at the same time. Try again.";
export const TOO_SLOW = "That took too long. Try again or narrow it down.";
export const NO_RESPONSE = "The remote service did not respond in time.";
export const DATABASE_DOWN = "The database is not reachable right now. Try again in a moment.";

const MAX_ISSUES = 5;
const MAX_ISSUE_MESSAGE = 160;
const MAX_DEPTH = 6;

/** Unique constraints a person can hit through the UI, by name, in words. */
const UNIQUE_MEANING: Record<string, string> = {
  tenants_slug_unique: "A customer with that slug already exists.",
  user_email_unique: "A user with that email address already exists.",
  sso_provider_provider_id_unique: "An SSO provider with that id already exists.",
  roles_pkey: "A role with that key already exists.",
  role_assignments_unique: "That user already has that role.",
  monitored_domains_tenant_name: "That domain is already monitored for this customer.",
  partner_consents_pair: "That partner already has a consent record for this customer.",
  detection_deployments_unique: "That rule is already deployed to that customer.",
  sigma_rule_versions_unique: CONCURRENT_CHANGE,
  ir_plans_tenant_version: CONCURRENT_CHANGE,
};

type Issue = { path?: readonly PropertyKey[]; message?: unknown; code?: unknown };
type PgError = Error & { code: string; constraint_name?: string; table_name?: string; column_name?: string };
type NodeError = Error & { code?: unknown; hostname?: unknown; host?: unknown };

/** The error and its causes, outermost first. */
function chain(err: unknown): unknown[] {
  const out: unknown[] = [];
  for (let e = err, i = 0; e != null && i < MAX_DEPTH && !out.includes(e); i++) {
    out.push(e);
    e = typeof e === "object" ? (e as { cause?: unknown }).cause : undefined;
  }
  return out;
}

const words = (s: string) => s.replace(/[_-]+/g, " ").trim();
// Schema identifiers only: anything else could be a key the caller typed.
const IDENT = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;
const pathSegment = (p: PropertyKey) => (typeof p === "number" ? String(p) : typeof p === "string" && IDENT.test(p) ? p : "…");

function isZod(err: unknown): err is { issues: Issue[] } {
  return !!err && typeof err === "object" && "issues" in err && Array.isArray((err as { issues: unknown }).issues);
}

function describeIssues(issues: Issue[]): string {
  if (!issues.length) return "Some fields are invalid.";
  const parts = issues.slice(0, MAX_ISSUES).map((i) => {
    const path = i.path?.length ? i.path.map(pathSegment).join(".") : "value";
    // Zod names the rule, not the input; unrecognised-key issues would list the caller's own keys.
    const rule = i.code === "unrecognized_keys" ? "has fields that are not allowed" : String(i.message ?? "is invalid").replace(/\s+/g, " ").slice(0, MAX_ISSUE_MESSAGE);
    return `${path}: ${rule}`;
  });
  const more = issues.length > MAX_ISSUES ? `; and ${issues.length - MAX_ISSUES} more` : "";
  return `Some fields are invalid: ${parts.join("; ")}${more}.`;
}

function isPg(e: unknown): e is PgError {
  if (!(e instanceof Error)) return false;
  const code = (e as { code?: unknown }).code;
  return typeof code === "string" && /^[0-9A-Z]{5}$/.test(code) && (e.name === "PostgresError" || "severity" in e || "routine" in e);
}

function describePg(e: PgError): string | null {
  switch (e.code) {
    case "23505": {
      const known = e.constraint_name ? UNIQUE_MEANING[e.constraint_name] : undefined;
      if (known) return known;
      return e.table_name && IDENT.test(e.table_name) ? `That already exists (${words(e.table_name)}).` : "That already exists.";
    }
    case "23503":
      // The same code covers both directions: inserting a dangling reference, or deleting a row others point at.
      return /^update or delete on/.test(e.message) ? "It is still in use elsewhere, so it can't be removed." : "It refers to something that no longer exists.";
    case "23502":
      return e.column_name && IDENT.test(e.column_name) ? `A required field is missing: ${words(e.column_name)}.` : "A required field is missing.";
    case "23514":
      return "A value is outside what is allowed.";
    case "22001":
      return "A value is too long.";
    case "22003":
      return "A number is out of range.";
    case "22P02":
    case "22007":
    case "22008":
      return "A value is not in the expected format.";
    case "40001":
    case "40P01":
    case "55P03":
      return CONCURRENT_CHANGE;
    case "57014":
      return TOO_SLOW;
    case "42501":
      return "You don't have permission to do that.";
    case "53300":
    case "57P01":
    case "57P03":
      return DATABASE_DOWN;
    default:
      return e.code.startsWith("08") ? DATABASE_DOWN : null;
  }
}

const TIMEOUT_CODES = new Set(["ETIMEDOUT", "ESOCKETTIMEDOUT", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT"]);
const REACH_REASON: Record<string, string> = {
  ECONNREFUSED: "connection refused",
  ENOTFOUND: "host name not found",
  EAI_AGAIN: "host name lookup failed",
  ECONNRESET: "connection reset",
  EPIPE: "connection reset",
  UND_ERR_SOCKET: "connection reset",
  EHOSTUNREACH: "host unreachable",
  ENETUNREACH: "network unreachable",
};
const POSTGRES_CONNECTION = new Set(["CONNECTION_CLOSED", "CONNECTION_ENDED", "CONNECTION_DESTROYED", "CONNECT_TIMEOUT"]);
const TLS_CODE = /^(CERT_|ERR_TLS_|DEPTH_ZERO_SELF_SIGNED_CERT$|SELF_SIGNED_CERT_IN_CHAIN$|UNABLE_TO_(VERIFY|GET)_)/;
const BUILT_IN = [TypeError, RangeError, ReferenceError, SyntaxError];
const HOST = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

/** A host name the error itself carries (what the admin configured), when it is a plain name. */
function hostOf(errs: unknown[]): string | null {
  for (const e of errs) {
    const n = e as NodeError;
    for (const h of [n?.hostname, n?.host]) if (typeof h === "string" && HOST.test(h)) return h;
  }
  return null;
}

export function explainActionError(err: unknown): ExplainedError | null {
  if (isZod(err)) return { message: describeIssues(err.issues), log: false };

  const errs = chain(err);
  const pg = errs.find(isPg);
  if (pg) {
    const message = describePg(pg);
    return message ? { message, log: true } : null;
  }

  const egress = errs.find((e): e is Error => e instanceof Error && e.name === "EgressDenied");
  // Our own policy message: names the refused address class, never secrets.
  if (egress) return { message: `Blocked by the outbound network policy: ${egress.message.replace(/^egress refused:\s*/, "")}.`, log: true };

  const codes = errs.map((e) => (e as NodeError)?.code).filter((c): c is string => typeof c === "string");
  const viaDatabase = errs.some((e) => e instanceof DrizzleQueryError);
  if (codes.some((c) => POSTGRES_CONNECTION.has(c)) || (viaDatabase && codes.some((c) => c in REACH_REASON || TIMEOUT_CODES.has(c)))) {
    return { message: DATABASE_DOWN, log: true };
  }

  // AbortSignal.timeout() rejects with a DOMException named TimeoutError.
  const names = errs.map((e) => (e as { name?: unknown })?.name);
  if (names.includes("AbortError") || names.includes("TimeoutError") || codes.some((c) => TIMEOUT_CODES.has(c))) {
    return { message: NO_RESPONSE, log: true };
  }

  const host = hostOf(errs);
  const target = host ? `Could not reach ${host}` : "Could not reach the remote service";
  if (codes.some((c) => TLS_CODE.test(c))) return { message: `${target}: its TLS certificate is not trusted.`, log: true };
  const reason = codes.map((c) => REACH_REASON[c]).find(Boolean);
  if (reason) return { message: `${target} (${reason}).`, log: true };
  if (err instanceof TypeError && err.message === "fetch failed") return { message: `${target}.`, log: true };

  // Our own errors carry a message written for people. Driver and library errors carry a code or a
  // cause, and built-in errors (TypeError and friends) are bugs whose text means nothing to a user.
  if (err instanceof Error && !("code" in err) && !("cause" in err) && !(err instanceof DrizzleQueryError) && !BUILT_IN.some((C) => err instanceof C)) {
    return { message: err.message, log: true };
  }
  return null;
}

/** A short id for the generic message; the full request id is on the log line too. */
export function errorRef(requestId: string | undefined): string {
  const id = requestId?.replace(/[^A-Za-z0-9]/g, "") ?? "";
  return (id || crypto.randomUUID().replace(/-/g, "")).slice(0, 8);
}

export function genericActionError(ref: string): string {
  return `Something went wrong (ref ${ref}). The error has been logged.`;
}
