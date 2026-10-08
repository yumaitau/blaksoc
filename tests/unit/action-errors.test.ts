import { DrizzleQueryError } from "drizzle-orm";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

const state = vi.hoisted(() => ({ requestId: "4f2a9c1e-7b3d-4e5f-9a0b-1c2d3e4f5a6b" as string | null, signedIn: true }));

vi.mock("server-only", () => ({}));
vi.mock("next/headers", () => ({ headers: async () => new Headers(state.requestId ? { "x-request-id": state.requestId } : {}) }));
vi.mock("@/lib/auth/session", () => ({ currentAccess: async () => (state.signedIn ? { principal: { userId: "u-1" } } : null) }));

const { CONCURRENT_CHANGE, DATABASE_DOWN, NO_RESPONSE, TOO_SLOW, errorRef, explainActionError } = await import("@/lib/action-errors");
const { withAccess } = await import("@/lib/actions");
const { AccessDenied } = await import("@/lib/auth/access");
const { EgressDenied } = await import("@/lib/net/egress");
const { setLogSink } = await import("@/lib/obs/log");

/** What postgres.js throws, wrapped the way drizzle wraps it (the SQL and parameters ride on the wrapper). */
function pgError(fields: Record<string, unknown>) {
  const pg = Object.assign(new Error(String(fields.message ?? "db error")), { name: "PostgresError", severity: "ERROR", ...fields });
  return new DrizzleQueryError('insert into "tenants" ("slug") values ($1)', ["acme-secret-value"], pg);
}

function networkError(code: string, extra: Record<string, unknown> = {}) {
  return new TypeError("fetch failed", { cause: Object.assign(new Error(`${code} something`), { code, ...extra }) });
}

function capture() {
  const lines: Record<string, unknown>[] = [];
  setLogSink((line) => void lines.push(JSON.parse(line)));
  return lines;
}

afterEach(() => {
  setLogSink(undefined);
  state.requestId = "4f2a9c1e-7b3d-4e5f-9a0b-1c2d3e4f5a6b";
  state.signedIn = true;
});

describe("explainActionError", () => {
  it("names Zod fields and rules without echoing submitted values", () => {
    const schema = z.object({ apiUrl: z.url(), port: z.number().int().max(65535), tags: z.array(z.string().max(3)) }).strict();
    const r = schema.safeParse({ apiUrl: "not a url hunter2", port: 99999, tags: ["okay", "toolong-secret"], extra: "x" });
    const out = explainActionError(r.error);
    expect(out?.log).toBe(false);
    expect(out?.message).toMatch(/^Some fields are invalid: /);
    expect(out?.message).toContain("apiUrl: ");
    expect(out?.message).toContain("port: ");
    expect(out?.message).toContain("tags.0: ");
    expect(out?.message).toContain("value: has fields that are not allowed");
    for (const leaked of ["hunter2", "99999", "toolong-secret", "extra"]) expect(out?.message).not.toContain(leaked);
  });

  it("caps the issue list and hides path keys that are not schema identifiers", () => {
    const issues = Array.from({ length: 8 }, (_, i) => ({ path: ["config", i === 0 ? "jane@example.com" : `f${i}`], message: "Required" }));
    const out = explainActionError({ issues });
    expect(out?.message).toContain("config.…: Required");
    expect(out?.message).not.toContain("jane@example.com");
    expect(out?.message).toMatch(/; and 3 more\.$/);
  });

  it("maps Postgres codes to plain language and never shows SQL, parameters or detail", () => {
    const cases: [Record<string, unknown>, string][] = [
      [{ code: "23505", constraint_name: "tenants_slug_unique", table_name: "tenants", detail: "Key (slug)=(acme-secret-value) already exists." }, "A customer with that slug already exists."],
      [{ code: "23505", constraint_name: "saved_views_pkey", table_name: "saved_views" }, "That already exists (saved views)."],
      [{ code: "23505" }, "That already exists."],
      [{ code: "23503", message: 'insert or update on table "alerts" violates foreign key constraint' }, "It refers to something that no longer exists."],
      [{ code: "23503", message: 'update or delete on table "roles" violates foreign key constraint' }, "It is still in use elsewhere, so it can't be removed."],
      [{ code: "23502", column_name: "name" }, "A required field is missing: name."],
      [{ code: "40001" }, CONCURRENT_CHANGE],
      [{ code: "40P01" }, CONCURRENT_CHANGE],
      [{ code: "55P03" }, CONCURRENT_CHANGE],
      [{ code: "57014" }, TOO_SLOW],
      [{ code: "08006" }, DATABASE_DOWN],
    ];
    for (const [fields, message] of cases) {
      const out = explainActionError(pgError(fields));
      expect(out, String(fields.code)).toEqual({ message, log: true });
      expect(out?.message).not.toMatch(/acme-secret-value|insert into|params/);
    }
  });

  it("leaves unknown database errors to the generic message", () => {
    expect(explainActionError(pgError({ code: "XX000" }))).toBeNull();
    expect(explainActionError(new DrizzleQueryError("select 1", []))).toBeNull();
  });

  it("explains egress refusals, timeouts and unreachable hosts", () => {
    expect(explainActionError(new TypeError("fetch failed", { cause: new EgressDenied("10.0.0.5 is not a public address") }))?.message).toBe(
      "Blocked by the outbound network policy: 10.0.0.5 is not a public address.",
    );
    expect(explainActionError(new DOMException("The operation timed out.", "TimeoutError"))?.message).toBe(NO_RESPONSE);
    expect(explainActionError(Object.assign(new Error("aborted"), { name: "AbortError" }))?.message).toBe(NO_RESPONSE);
    expect(explainActionError(networkError("UND_ERR_CONNECT_TIMEOUT"))?.message).toBe(NO_RESPONSE);
    expect(explainActionError(networkError("ENOTFOUND", { hostname: "wazuh.acme.internal" }))?.message).toBe("Could not reach wazuh.acme.internal (host name not found).");
    expect(explainActionError(networkError("ECONNREFUSED", { address: "10.1.2.3", port: 55000 }))?.message).toBe("Could not reach the remote service (connection refused).");
    expect(explainActionError(networkError("DEPTH_ZERO_SELF_SIGNED_CERT"))?.message).toBe("Could not reach the remote service: its TLS certificate is not trusted.");
    expect(explainActionError(new TypeError("fetch failed"))?.message).toBe("Could not reach the remote service.");
    // A host that is not a plain name is not repeated back.
    expect(explainActionError(networkError("ENOTFOUND", { hostname: "evil\nhost" }))?.message).toBe("Could not reach the remote service (host name not found).");
  });

  it("calls a refused database connection a database problem, not a remote service", () => {
    const refused = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:5432"), { code: "ECONNREFUSED" });
    expect(explainActionError(new DrizzleQueryError("select 1", [], refused))?.message).toBe(DATABASE_DOWN);
    expect(explainActionError(Object.assign(new Error("write CONNECTION_CLOSED db:5432"), { code: "CONNECTION_CLOSED" }))?.message).toBe(DATABASE_DOWN);
  });

  it("shows our own messages but not driver, library or built-in error text", () => {
    expect(explainActionError(new Error("Test cases must be a non-empty JSON array."))).toEqual({ message: "Test cases must be a non-empty JSON array.", log: true });
    expect(explainActionError(Object.assign(new Error("ERR_SOMETHING internal"), { code: "ERR_SOMETHING" }))).toBeNull();
    expect(explainActionError(new Error("wrapped", { cause: new Error("inner") }))).toBeNull();
    expect(explainActionError(new TypeError("Cannot read properties of undefined (reading 'id')"))).toBeNull();
    expect(explainActionError("a string")).toBeNull();
  });

  it("derives a short reference from the request id, or makes one up outside a request", () => {
    expect(errorRef("4f2a9c1e-7b3d-4e5f-9a0b-1c2d3e4f5a6b")).toBe("4f2a9c1e");
    expect(errorRef("req-web-0001")).toBe("reqweb00");
    expect(errorRef(undefined)).toMatch(/^[0-9a-f]{8}$/);
  });
});

describe("withAccess error mapping", () => {
  it("returns data on success", async () => {
    expect(await withAccess(async () => 42)).toEqual({ ok: true, data: 42 });
  });

  it("asks for a new sign-in when the session is gone", async () => {
    state.signedIn = false;
    expect(await withAccess(async () => 1)).toEqual({ ok: false, error: "Your session has expired. Sign in again." });
  });

  it("explains permission rules and does not log them", async () => {
    const lines = capture();
    expect(await withAccess(async () => { throw new AccessDenied("alert:assign required"); })).toEqual({ ok: false, error: "Not permitted: alert:assign required." });
    expect(await withAccess(async () => { throw new AccessDenied(); })).toEqual({ ok: false, error: "You don't have permission to do that." });
    expect(lines).toEqual([]);
  });

  it("does not log validation mistakes but logs known failures", async () => {
    const lines = capture();
    const invalid = await withAccess(async () => z.object({ name: z.string().min(1) }).parse({ name: "" }));
    expect(invalid.ok).toBe(false);
    expect(lines).toEqual([]);
    expect(await withAccess(async () => { throw pgError({ code: "40001" }); })).toEqual({ ok: false, error: CONCURRENT_CHANGE });
    expect(lines).toEqual([expect.objectContaining({ level: "error", msg: "server action failed", userId: "u-1", requestId: state.requestId })]);
  });

  it("gives unknown failures a reference that matches the log line, and leaks nothing", async () => {
    const lines = capture();
    const res = await withAccess(async () => { throw pgError({ code: "XX000", message: "internal: relation secret_table" }); });
    expect(res).toEqual({ ok: false, error: "Something went wrong (ref 4f2a9c1e). The error has been logged." });
    expect(lines).toEqual([expect.objectContaining({ level: "error", ref: "4f2a9c1e", requestId: state.requestId })]);
    expect(JSON.stringify(res)).not.toMatch(/secret_table|acme-secret-value|insert into/);
    // The log line keeps the error for support but scrubs bound parameters.
    expect(JSON.stringify(lines)).not.toContain("acme-secret-value");
  });

  it("still gives a reference outside a request", async () => {
    state.requestId = null;
    const lines = capture();
    const res = await withAccess(async () => { throw new TypeError("x is not a function"); });
    const ref = /ref ([0-9a-f]{8})\)/.exec(res.ok ? "" : res.error)?.[1];
    expect(ref).toBeDefined();
    expect(lines[0]).toMatchObject({ ref });
  });
});
