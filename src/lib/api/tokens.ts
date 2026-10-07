import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** Prefixes let secret scanners recognise leaked credentials. */
export const SECRET_PREFIX = "bss_";
export const TOKEN_PREFIX = "bsa_";
/** Access token lifetime. Short, because a token is not bound to the caller. */
export const TOKEN_TTL_SECONDS = 15 * 60;

const BODY = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** 256 random bits. Hashing with SHA-256 is enough at that entropy; a slow KDF adds nothing. */
export function newSecret(prefix: typeof SECRET_PREFIX | typeof TOKEN_PREFIX): string {
  return `${prefix}${randomBytes(32).toString("base64url")}`;
}

export function hashSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

/** Constant-time check of a presented secret against a stored hash. */
export function secretMatches(secret: string, storedHash: string): boolean {
  const a = Buffer.from(hashSecret(secret), "hex");
  const b = Buffer.from(storedHash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Well-formed blakSOC secret or token with the given prefix. Rejects anything else before a DB lookup. */
export function wellFormed(value: string, prefix: typeof SECRET_PREFIX | typeof TOKEN_PREFIX): boolean {
  return value.startsWith(prefix) && BODY.test(value.slice(prefix.length));
}

/** The token from `Authorization: Bearer <token>`, or null. */
export function parseBearer(header: string | null): string | null {
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header ?? "");
  return m && wellFormed(m[1]!, TOKEN_PREFIX) ? m[1]! : null;
}

export type ClientCredentials = { clientId: string; clientSecret: string };

/**
 * Client credentials from HTTP Basic (RFC 6749 §2.3.1, form-encoded halves) or the request body.
 * Both at once is ambiguous and refused.
 */
export function parseClientCredentials(header: string | null, body: URLSearchParams): ClientCredentials | null {
  const bodyId = body.get("client_id");
  const bodySecret = body.get("client_secret");
  const basic = /^Basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(header ?? "");
  let creds: ClientCredentials | null = null;
  if (basic) {
    if (bodyId || bodySecret) return null;
    const decoded = Buffer.from(basic[1]!, "base64").toString("utf8");
    const i = decoded.indexOf(":");
    if (i < 0) return null;
    try {
      creds = { clientId: decodeURIComponent(decoded.slice(0, i)), clientSecret: decodeURIComponent(decoded.slice(i + 1)) };
    } catch {
      return null;
    }
  } else if (bodyId && bodySecret) {
    creds = { clientId: bodyId, clientSecret: bodySecret };
  }
  if (!creds || !UUID.test(creds.clientId) || !wellFormed(creds.clientSecret, SECRET_PREFIX)) return null;
  return creds;
}
