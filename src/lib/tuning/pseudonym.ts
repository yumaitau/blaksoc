import { createHmac, hkdfSync } from "node:crypto";

/**
 * Opaque, stable ids for the tuning API, so an external agent can track a pattern or a tenant across runs
 * without ever learning which customer it is. Keyed by HKDF from the server secret: rotating
 * BETTER_AUTH_SECRET gives every pattern and tenant a new id (the registry then fills again on the next list).
 */

const INFO = "blaksoc tuning pseudonyms v1";

export function pseudonymKey(secret: string): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, "blaksoc-tuning", INFO, 32));
}

const mac = (key: Buffer, value: string) => createHmac("sha256", key).update(value).digest();

/** "P-" + 22 url-safe characters (128 bits). */
export function patternIdFor(key: Buffer, tenantId: string, source: string, ruleId: string): string {
  return `P-${mac(key, `pattern\0${tenantId}\0${source}\0${ruleId}`).subarray(0, 16).toString("base64url")}`;
}

/** "T-3f9a1c": short and readable; unique enough to tell a fleet's tenants apart, never reversible. */
export function tenantRefFor(key: Buffer, tenantId: string): string {
  return `T-${mac(key, `tenant\0${tenantId}`).subarray(0, 3).toString("hex")}`;
}

export const PATTERN_ID = /^P-[A-Za-z0-9_-]{22}$/;
