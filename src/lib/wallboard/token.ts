import { createHmac, timingSafeEqual } from "node:crypto";

const TOKEN = /^v1\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([1-9][0-9]{12})\.([A-Za-z0-9_-]{43})$/;

function signature(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(`blaksoc:wallboard:v1:${payload}`).digest("base64url");
}

export function signWallboardToken(id: string, expiresAt: Date, secret: string): string {
  const payload = `v1.${id}.${expiresAt.getTime()}`;
  return `${payload}.${signature(payload, secret)}`;
}

/** A signature grants access only after the persisted link and issuer have also been checked. */
export function verifyWallboardToken(token: string, secret: string, now = new Date()): { id: string; expiresAt: Date } | null {
  const match = TOKEN.exec(token);
  if (!match) return null;
  const expiresAt = new Date(Number(match[2]));
  if (expiresAt <= now) return null;
  const payload = `v1.${match[1]}.${match[2]}`;
  const expected = Buffer.from(signature(payload, secret));
  const presented = Buffer.from(match[3]!);
  if (!timingSafeEqual(expected, presented)) return null;
  return { id: match[1]!, expiresAt };
}
