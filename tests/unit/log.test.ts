import { afterEach, describe, expect, it } from "vitest";
import { withObsContext } from "@/lib/obs/context";
import { logger, redact, scrub, setLogSink } from "@/lib/obs/log";

function capture() {
  const lines: string[] = [];
  setLogSink((line) => void lines.push(line));
  return lines;
}

afterEach(() => {
  setLogSink(undefined);
  delete process.env.LOG_LEVEL;
});

const SECRETS = [
  "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
  "hunter2-very-secret",
  "client-secret-value",
  "ZGV2LW9ubHkta2V5LWNoYW5nZS1tZS0zMi1ieXRlcyE=",
  "session-cookie-value",
  "s3cr3t-token",
  "wazuh-api-password",
];

describe("structured logger", () => {
  it("writes one JSON line with level, time, msg and the request/job correlation fields", () => {
    const lines = capture();
    withObsContext({ requestId: "req-12345678", jobId: "42", queue: "ingest", tenantId: "t-1" }, () => logger.warn("poll failed", { integrationId: "i-1" }));
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]!);
    expect(entry).toMatchObject({ level: "warn", msg: "poll failed", requestId: "req-12345678", jobId: "42", queue: "ingest", tenantId: "t-1", integrationId: "i-1", service: "web" });
    expect(Number.isNaN(Date.parse(entry.time))).toBe(false);
  });

  it("drops entries below LOG_LEVEL", () => {
    const lines = capture();
    process.env.LOG_LEVEL = "error";
    logger.warn("quiet");
    logger.error("loud");
    expect(lines.map((l) => JSON.parse(l).msg)).toEqual(["loud"]);
  });

  it("never writes secrets or raw event payloads", () => {
    const lines = capture();
    const headers = new Headers({ authorization: SECRETS[0]!, cookie: `better-auth.session_token=${SECRETS[4]}`, "content-type": "application/json" });
    const raw = { rule: { description: "Mimikatz on DC01" }, data: { win: { eventdata: { commandLine: "sekurlsa::logonpasswords" } } } };
    logger.error("request failed", {
      headers,
      config: { url: "https://wazuh.example:55000", username: "wazuh", password: SECRETS[1], clientSecret: SECRETS[2], apiKey: "k-1", nested: { accessToken: SECRETS[5] } },
      env: { BLAKSOC_ENCRYPTION_KEY: SECRETS[3], BETTER_AUTH_SECRET: SECRETS[1] },
      alert: { title: "Credential dumping", raw },
      raw,
      body: "<14>Oct  7 firewall: allow 10.0.0.1 -> 8.8.8.8",
      err: new Error(`connect failed for https://wazuh:${SECRETS[6]}@wazuh.example:55000/security/user/authenticate?token=${SECRETS[5]}`),
      usage: { inputTokens: 120, outputTokens: 40 },
    });
    const line = lines[0]!;
    for (const secret of SECRETS) expect(line).not.toContain(secret);
    expect(line).not.toContain("Mimikatz");
    expect(line).not.toContain("logonpasswords");
    expect(line).not.toContain("10.0.0.1");
    const entry = JSON.parse(line);
    expect(entry.headers).toEqual({ authorization: "[redacted]", cookie: "[redacted]", "content-type": "application/json" });
    expect(entry.config.username).toBe("wazuh");
    expect(entry.config.url).toBe("https://wazuh.example:55000");
    expect(entry.alert).toBe("[omitted]");
    expect(entry.raw).toBe("[omitted]");
    // Token counts are usage, not credentials.
    expect(entry.usage).toEqual({ inputTokens: 120, outputTokens: 40 });
    expect(entry.err.message).toContain("wazuh:[redacted]@wazuh.example");
    expect(entry.err.message).toContain("token=[redacted]");
  });

  it("scrubs credentials from free text, including the message itself", () => {
    expect(scrub("Authorization: Bearer abc.def.ghi failed")).toBe("Authorization: Bearer [redacted] failed");
    expect(scrub('{"client_secret":"xyz","name":"ok"}')).toBe('{"client_secret":"[redacted]","name":"ok"}');
    expect(scrub("callback ?code=4/0Aabc&state=1")).toBe("callback ?code=[redacted]&state=1");
    expect(scrub("postgres://blaksoc_app:change-me@db:5432/blaksoc")).toBe("postgres://blaksoc_app:[redacted]@db:5432/blaksoc");
    // Drizzle appends bound parameters (alert JSON, ciphertext) to query errors.
    expect(scrub('Failed query: insert into "alerts" values ($1)\nparams: {"raw":{"secret":1}}')).toBe('Failed query: insert into "alerts" values ($1)\nparams: [redacted]');
    const lines = capture();
    logger.warn("retrying with password=hunter2 for user");
    expect(lines[0]).not.toContain("hunter2");
  });

  it("survives cycles, deep nesting and odd values", () => {
    const a: Record<string, unknown> = { name: "a" };
    a.self = a;
    const out = redact({ a, big: 10n, when: new Date(0), buf: new Uint8Array([1, 2]) }) as Record<string, unknown>;
    expect((out.a as Record<string, unknown>).self).toBe("[circular]");
    expect(out.big).toBe("10");
    expect(out.when).toBe("1970-01-01T00:00:00.000Z");
    expect(out.buf).toBe("[binary]");
  });
});
