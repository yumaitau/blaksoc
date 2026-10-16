import { eq, inArray } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { adminDb } from "@/db/client";
import { assets, assetSources, integrations, tenantPlans, tenants } from "@/db/schema";
import type { NormalisedSoftware } from "@/lib/providers/types";

type Answer = { software: NormalisedSoftware[]; complete: boolean } | Error;
const answers = new Map<string, Answer>();
const broken = new Set<string>();

// Only this file's integrations get a stub provider; every other enabled integration reports no software.
vi.mock("@/lib/connectors/instances", async (orig) => {
  const real = await orig<typeof import("@/lib/connectors/instances")>();
  return {
    ...real,
    eventProvider: (row: { id: string }) => {
      if (broken.has(row.id)) throw new Error("invalid config");
      const answer = answers.get(row.id);
      if (!answer) return {};
      return { getSoftware: async () => { if (answer instanceof Error) throw answer; return answer; } };
    },
  };
});

const { syncAllSoftware } = await import("@/worker/jobs/ingest");

const stamp = `software-${Date.now()}`;
let tenantId: string, first: string, second: string, integrationId: string, brokenId: string;
const softwareOf = async (id: string) => (await adminDb().select({ software: assets.software }).from(assets).where(eq(assets.id, id)))[0]!.software;
const STALE = [{ name: "old-agent", version: "1" }];

beforeAll(async () => {
  const [t] = await adminDb().insert(tenants).values({ name: "Software sync", slug: stamp, kind: "customer" }).returning();
  tenantId = t!.id;
  // Wazuh collection needs the Standard tier.
  await adminDb().insert(tenantPlans).values({ tenantId, tier: "standard" });
  // Created first, so a failure here must not stop the integration after it.
  const [bad] = await adminDb().insert(integrations).values({ tenantId, category: "siem", provider: "wazuh", name: `${stamp}-broken` }).returning();
  const [row] = await adminDb().insert(integrations).values({ tenantId, category: "siem", provider: "wazuh", name: stamp }).returning();
  brokenId = bad!.id;
  integrationId = row!.id;
  broken.add(brokenId);
  const made = await adminDb().insert(assets).values([
    { tenantId, name: `${stamp}-a`, kind: "endpoint" },
    { tenantId, name: `${stamp}-b`, kind: "endpoint" },
  ]).returning();
  [first, second] = made.map((a) => a.id) as [string, string];
  await adminDb().insert(assetSources).values([
    { tenantId, assetId: first, integrationId, externalId: "001" },
    { tenantId, assetId: second, integrationId, externalId: "002" },
  ]);
});

beforeEach(async () => {
  await adminDb().update(assets).set({ software: STALE }).where(inArray(assets.id, [first, second]));
});

afterAll(async () => {
  if (tenantId) await adminDb().delete(tenants).where(eq(tenants.id, tenantId));
});

describe("software sync", () => {
  it("replaces reported lists and clears agents that report nothing, past a broken integration", async () => {
    answers.set(integrationId, { software: [{ assetExternalId: "001", name: "openssl", version: "3.0.2" }], complete: true });
    await syncAllSoftware(() => {});
    expect(await softwareOf(first)).toEqual([{ name: "openssl", version: "3.0.2" }]);
    expect(await softwareOf(second)).toEqual([]);
  });

  it("leaves agents a truncated answer did not reach", async () => {
    answers.set(integrationId, { software: [{ assetExternalId: "001", name: "curl", version: "8" }], complete: false });
    await syncAllSoftware(() => {});
    expect(await softwareOf(first)).toEqual([{ name: "curl", version: "8" }]);
    expect(await softwareOf(second)).toEqual(STALE);
  });

  it("records a failed sync on the integration without marking it down", async () => {
    answers.set(integrationId, new Error("403 Forbidden"));
    await adminDb().update(integrations).set({ status: "healthy" }).where(eq(integrations.id, integrationId));
    await syncAllSoftware(() => {});
    const [row] = await adminDb().select().from(integrations).where(eq(integrations.id, integrationId));
    expect(row!.lastError).toBe("Software inventory: 403 Forbidden");
    expect(row!.status).toBe("healthy");
    expect(await softwareOf(first)).toEqual(STALE);
  });
});
