import { Redis } from "ioredis";
import { env } from "./env";

const g = globalThis as unknown as { __blaksocRedis?: Redis; __blaksocRedisSub?: Redis };

export function redis(): Redis {
  g.__blaksocRedis ??= new Redis(env().REDIS_URL, { maxRetriesPerRequest: null, lazyConnect: false });
  return g.__blaksocRedis;
}

/** BullMQ requires a dedicated connection config rather than a shared client for blocking commands. */
export function redisConnectionOptions() {
  const u = new URL(env().REDIS_URL);
  return {
    host: u.hostname,
    port: Number(u.port || 6379),
    username: u.username || undefined,
    password: u.password || undefined,
    // Same logical database as redis(); without it queues and schedulers land in db 0.
    db: Number(u.pathname.slice(1)) || 0,
    tls: u.protocol === "rediss:" ? {} : undefined,
    maxRetriesPerRequest: null,
  };
}

export function newRedis(): Redis {
  return new Redis(env().REDIS_URL, { maxRetriesPerRequest: null });
}
