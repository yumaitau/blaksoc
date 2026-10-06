import { beforeEach, describe, expect, it, vi } from "vitest";

const calls = { redisGet: 0, dbSelect: 0 };

vi.mock("@/lib/redis", () => ({
  redis: () => ({
    get: async () => {
      calls.redisGet++;
      await new Promise((r) => setTimeout(r, 10));
      return "7";
    },
  }),
}));

vi.mock("@/db/client", () => ({
  systemDb: () => ({
    select: () => ({
      from: () => ({
        where: async () => {
          calls.dbSelect++;
          return [{ config: { events: ["incident.created"] } }];
        },
      }),
    }),
  }),
}));

describe("subscribed event type cache", () => {
  beforeEach(() => {
    calls.redisGet = 0;
    calls.dbSelect = 0;
  });

  it("shares one refresh between events that arrive together", async () => {
    const { subscribedEventTypes } = await import("@/lib/connectors/subscriptions");
    const results = await Promise.all(Array.from({ length: 5 }, () => subscribedEventTypes(1_000_000)));
    expect(results.every((r) => r.has("incident.created"))).toBe(true);
    expect(calls).toEqual({ redisGet: 1, dbSelect: 1 });
    // Within the version check interval nothing is read again.
    await subscribedEventTypes(1_002_000);
    expect(calls).toEqual({ redisGet: 1, dbSelect: 1 });
    // After it, only the version is read while it is unchanged.
    await Promise.all([subscribedEventTypes(1_010_000), subscribedEventTypes(1_010_000)]);
    expect(calls).toEqual({ redisGet: 2, dbSelect: 1 });
  });
});
