/**
 * Sign-in rate limits shared by every web replica. better-auth's default store is per process,
 * so with N replicas an attacker gets N times the limit. Counters live in Redis as fixed windows.
 * If Redis does not answer within REDIS_TIMEOUT_MS the request is judged by a per-process
 * counter instead: sign-in (including break-glass) keeps working during a Redis outage, at the
 * weaker per-replica limit.
 */
export type RateRule = { window: number; max: number };
export type RateDecision = { allowed: boolean; retryAfter: number | null };

/** The slice of an ioredis client this store uses. */
export type RateRedis = {
  multi(): { incr(key: string): unknown; expire(key: string, seconds: number, mode: "NX"): unknown; ttl(key: string): unknown; exec(): Promise<[Error | null, unknown][] | null> };
};

export const REDIS_TIMEOUT_MS = 500;

function memoryStore() {
  const counters = new Map<string, { count: number; resetAt: number }>();
  return (key: string, rule: RateRule, now = Date.now()): RateDecision => {
    if (counters.size > 50_000) for (const [k, v] of counters) if (v.resetAt <= now) counters.delete(k);
    const cur = counters.get(key);
    const entry = cur && cur.resetAt > now ? cur : { count: 0, resetAt: now + rule.window * 1000 };
    entry.count++;
    counters.set(key, entry);
    return entry.count <= rule.max ? { allowed: true, retryAfter: null } : { allowed: false, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
  };
}

/** `onFallback` is called at most once a minute while Redis is unavailable. */
export function sharedRateLimitStore(client: () => RateRedis, onFallback: (err: unknown) => void = () => {}) {
  const local = memoryStore();
  let lastWarned = 0;
  return {
    async consume(key: string, rule: RateRule): Promise<RateDecision> {
      const k = `blaksoc:ratelimit:${key}`;
      try {
        const tx = client().multi();
        tx.incr(k);
        tx.expire(k, rule.window, "NX");
        tx.ttl(k);
        const timeout = new Promise<never>((_, reject) => setTimeout(() => reject(new Error("redis rate limit timeout")), REDIS_TIMEOUT_MS).unref?.());
        const res = await Promise.race([tx.exec(), timeout]);
        if (!res) throw new Error("redis rate limit transaction aborted");
        const failed = res.find(([err]) => err);
        if (failed) throw failed[0];
        const count = Number(res[0]![1]);
        const ttl = Number(res[2]![1]);
        return count <= rule.max ? { allowed: true, retryAfter: null } : { allowed: false, retryAfter: ttl > 0 ? ttl : rule.window };
      } catch (err) {
        if (Date.now() - lastWarned > 60_000) {
          lastWarned = Date.now();
          onFallback(err);
        }
        return local(key, rule);
      }
    },
  };
}
