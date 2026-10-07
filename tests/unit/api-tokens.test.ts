import { describe, expect, it } from "vitest";
import { hashSecret, newSecret, parseBearer, parseClientCredentials, SECRET_PREFIX, secretMatches, TOKEN_PREFIX, TOKEN_TTL_SECONDS, wellFormed } from "@/lib/api/tokens";

const CLIENT = "6f1c2b8e-4a1d-4c3b-9e2f-1a2b3c4d5e6f";
const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

describe("service secrets and tokens", () => {
  it("are prefixed, 256-bit and unique", () => {
    const a = newSecret(SECRET_PREFIX);
    const b = newSecret(SECRET_PREFIX);
    expect(a).not.toBe(b);
    expect(wellFormed(a, SECRET_PREFIX)).toBe(true);
    expect(wellFormed(a, TOKEN_PREFIX)).toBe(false);
    expect(Buffer.from(a.slice(SECRET_PREFIX.length), "base64url")).toHaveLength(32);
  });

  it("store only a SHA-256 and compare against it", () => {
    const secret = newSecret(SECRET_PREFIX);
    const stored = hashSecret(secret);
    expect(stored).toMatch(/^[0-9a-f]{64}$/);
    expect(stored).not.toContain(secret.slice(4));
    expect(secretMatches(secret, stored)).toBe(true);
    expect(secretMatches(newSecret(SECRET_PREFIX), stored)).toBe(false);
    expect(secretMatches(secret, "not-hex")).toBe(false);
  });

  it("live at most 15 minutes", () => {
    expect(TOKEN_TTL_SECONDS).toBeLessThanOrEqual(15 * 60);
  });
});

describe("parseBearer", () => {
  const token = newSecret(TOKEN_PREFIX);
  it("accepts a well-formed access token", () => {
    expect(parseBearer(`Bearer ${token}`)).toBe(token);
    expect(parseBearer(`bearer ${token}`)).toBe(token);
  });

  it("rejects missing, malformed or wrong-kind credentials", () => {
    expect(parseBearer(null)).toBeNull();
    expect(parseBearer("")).toBeNull();
    expect(parseBearer(`Basic ${token}`)).toBeNull();
    expect(parseBearer(`Bearer ${newSecret(SECRET_PREFIX)}`)).toBeNull();
    expect(parseBearer(`Bearer ${token}x`)).toBeNull();
    expect(parseBearer(`Bearer ${token} extra`)).toBeNull();
  });
});

describe("parseClientCredentials", () => {
  const secret = newSecret(SECRET_PREFIX);
  it("reads HTTP Basic", () => {
    expect(parseClientCredentials(basic(CLIENT, secret), new URLSearchParams())).toEqual({ clientId: CLIENT, clientSecret: secret });
  });

  it("reads form fields", () => {
    expect(parseClientCredentials(null, new URLSearchParams({ client_id: CLIENT, client_secret: secret }))).toEqual({ clientId: CLIENT, clientSecret: secret });
  });

  it("refuses both at once, half a pair, or malformed values", () => {
    expect(parseClientCredentials(basic(CLIENT, secret), new URLSearchParams({ client_id: CLIENT }))).toBeNull();
    expect(parseClientCredentials(null, new URLSearchParams({ client_id: CLIENT }))).toBeNull();
    expect(parseClientCredentials(null, new URLSearchParams({ client_id: "not-a-uuid", client_secret: secret }))).toBeNull();
    expect(parseClientCredentials(null, new URLSearchParams({ client_id: CLIENT, client_secret: "password" }))).toBeNull();
    expect(parseClientCredentials(`Basic ${Buffer.from("no-colon").toString("base64")}`, new URLSearchParams())).toBeNull();
  });
});
