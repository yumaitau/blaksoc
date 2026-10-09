import { describe, expect, it } from "vitest";
import { signWallboardToken, verifyWallboardToken } from "@/lib/wallboard/token";

const secret = "test-wallboard-secret-with-at-least-32-characters";
const id = "00000000-0000-4000-8000-000000000001";
const now = new Date("2026-10-09T00:00:00Z");
const expiresAt = new Date(now.getTime() + 86_400_000);

describe("wallboard signatures", () => {
  it("authenticates the exact link and expiry", () => {
    const token = signWallboardToken(id, expiresAt, secret);
    expect(verifyWallboardToken(token, secret, now)).toEqual({ id, expiresAt });
    expect(verifyWallboardToken(token, `${secret}wrong`, now)).toBeNull();
    expect(verifyWallboardToken(token.replace(id, id.replace(/1$/, "2")), secret, now)).toBeNull();
    expect(verifyWallboardToken(token.replace(String(expiresAt.getTime()), String(expiresAt.getTime() + 1)), secret, now)).toBeNull();
  });

  it("fails closed at expiry and rejects malformed or noncanonical tokens", () => {
    const token = signWallboardToken(id, expiresAt, secret);
    expect(verifyWallboardToken(token, secret, expiresAt)).toBeNull();
    for (const value of ["", `${token}.x`, token.replace("v1.", "v2."), token.replace(id, "bad-id"), token.replace(String(expiresAt.getTime()), "01"), `${token}=`, "x".repeat(400)]) {
      expect(verifyWallboardToken(value, secret, now), value).toBeNull();
    }
  });
});
