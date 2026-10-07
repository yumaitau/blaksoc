import { describe, expect, it } from "vitest";
import { config } from "@/proxy";

const gated = (path: string) => new RegExp(`^${config.matcher[0]}$`).test(path);

describe("session proxy matcher", () => {
  it("does not send bearer-token machine endpoints to the login page", () => {
    expect(gated("/api/ingest/syslog")).toBe(false);
    expect(gated("/api/health")).toBe(false);
    expect(gated("/api/auth/sign-in")).toBe(false);
    expect(gated("/api/v1/alerts")).toBe(false);
    expect(gated("/api/v1/oauth/token")).toBe(false);
  });

  it("still gates the app and session-authenticated APIs", () => {
    expect(gated("/soc")).toBe(true);
    expect(gated("/api/stream")).toBe(true);
    expect(gated("/api/reports/abc/export")).toBe(true);
  });
});
