import { describe, expect, it } from "vitest";
import { sharedRateLimitStore, type RateRedis } from "@/lib/auth/rate-limit";

/** In-memory stand-in for the Redis MULTI the store sends: INCR, EXPIRE NX, TTL. */
function fakeRedis() {
  const counts = new Map<string, number>();
  const client: RateRedis = {
    multi() {
      const ops: (() => unknown)[] = [];
      const tx = {
        incr: (k: string) => ops.push(() => counts.set(k, (counts.get(k) ?? 0) + 1).get(k)),
        expire: () => ops.push(() => 1),
        ttl: () => ops.push(() => 42),
        exec: async () => ops.map((op) => [null, op()] as [null, unknown]),
      };
      return tx;
    },
  };
  return client;
}

describe("shared sign-in rate limit", () => {
  const rule = { window: 60, max: 3 };

  it("counts every replica's requests against one Redis counter", async () => {
    const redis = fakeRedis();
    const replicaA = sharedRateLimitStore(() => redis);
    const replicaB = sharedRateLimitStore(() => redis);
    const results = [await replicaA.consume("ip|/sign-in/email", rule), await replicaB.consume("ip|/sign-in/email", rule), await replicaA.consume("ip|/sign-in/email", rule), await replicaB.consume("ip|/sign-in/email", rule)];
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(results[3]!.retryAfter).toBe(42);
  });

  it("falls back to a per-process limit when Redis fails, and warns once", async () => {
    const warnings: unknown[] = [];
    const broken: RateRedis = { multi: () => { throw new Error("connection refused"); } };
    const store = sharedRateLimitStore(() => broken, (err) => warnings.push(err));
    const results = [];
    for (let i = 0; i < 4; i++) results.push((await store.consume("ip|/sign-in/email", rule)).allowed);
    expect(results).toEqual([true, true, true, false]);
    expect(warnings).toHaveLength(1);
  });
});
