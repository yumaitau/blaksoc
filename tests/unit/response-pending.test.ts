import { describe, expect, it } from "vitest";
import { responseHintOf } from "@/lib/soar/hint";
import { decidePending, isPendingResult, PENDING_TIMEOUT_MS } from "@/lib/soar/pending";

describe("playbook response hints", () => {
  it("reads the alerting PID and M365 ids from raw", () => {
    expect(responseHintOf({ alert: {}, process: { pid: 4242, name: "powershell.exe" } })).toEqual({ ruleId: undefined, grantId: undefined, process: "4242" });
    expect(responseHintOf({ ruleId: "r1" })).toEqual({ ruleId: "r1", grantId: undefined, process: undefined });
    expect(responseHintOf({ process: { pid: "4242" } })).toBeUndefined();
    expect(responseHintOf(null)).toBeUndefined();
  });

});

describe("pending response actions", () => {
  const at = new Date("2026-09-01T00:00:00.000Z");
  const later = (ms: number) => new Date(at.getTime() + ms);

  it("settles on the provider's terminal state", () => {
    expect(decidePending({ state: "succeeded", message: "done" }, at, later(1000))).toEqual({ final: true, ok: true, message: "done" });
    expect(decidePending({ state: "failed", message: "no isolation" }, at, later(1000))).toEqual({ final: true, ok: false, message: "no isolation" });
  });

  it("keeps waiting while pending, running, or unreachable inside the timeout", () => {
    expect(decidePending({ state: "pending", message: "queued" }, at, later(60_000))).toEqual({ final: false, state: { state: "pending", message: "queued" } });
    expect(decidePending({ state: "running", message: "running" }, at, later(PENDING_TIMEOUT_MS - 1))).toMatchObject({ final: false });
    expect(decidePending(null, at, later(60_000))).toEqual({ final: false, state: null });
  });

  it("fails at the timeout", () => {
    expect(decidePending({ state: "running", message: "running" }, at, later(PENDING_TIMEOUT_MS))).toEqual({ final: true, ok: false, message: "timed out waiting for endpoint after 15 min (last state: running)" });
    expect(decidePending(null, at, later(PENDING_TIMEOUT_MS + 1))).toMatchObject({ final: true, ok: false, message: expect.stringMatching(/^timed out waiting for endpoint/) });
    // A terminal answer that arrives late still wins over the timeout.
    expect(decidePending({ state: "succeeded", message: "done" }, at, later(PENDING_TIMEOUT_MS * 2))).toMatchObject({ ok: true });
  });

  it("recognises only complete pending results", () => {
    expect(isPendingResult({ message: "m", providerRef: "r", pending: true, assetExternalId: "a", dispatchedAt: at.toISOString() })).toBe(true);
    expect(isPendingResult({ message: "m", providerRef: "r" })).toBe(false);
    expect(isPendingResult({ message: "m", pending: true })).toBe(false);
    expect(isPendingResult(null)).toBe(false);
  });
});
