/** Batched vulnerability upserts: more rows than one batch, and a second sync updates rather than duplicates. */
import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { assets, tenants, vulnerabilities } from "@/db/schema";
import { DEFAULT_TENANT_SETTINGS } from "@/db/schema/platform";
import { redis } from "@/lib/redis";
import { storeVulnerabilities } from "@/worker/jobs/ingest";

let tenantId = "";
let assetId = "";

beforeAll(async () => {
  const [t] = await adminDb().insert(tenants).values({ name: "vuln store", slug: `vs-${randomUUID().slice(0, 8)}`, kind: "customer", sectors: ["SMB"], deploymentMode: "shared", settings: DEFAULT_TENANT_SETTINGS }).returning();
  tenantId = t!.id;
  const [a] = await adminDb().insert(assets).values({ tenantId, kind: "server", name: "host-1", hostname: "host-1" } as never).returning();
  assetId = a!.id;
});

afterAll(async () => {
  if (tenantId) await adminDb().delete(tenants).where(eq(tenants.id, tenantId));
  await redis().quit();
});

describe("storeVulnerabilities", () => {
  it("stores more than one batch and updates on the next sync", async () => {
    const rows = (cvss: number) => Array.from({ length: 1234 }, (_, i) => ({ tenantId, assetId, cve: `CVE-2026-${i}`, title: null, packageName: "openssl", packageVersion: "3.0.1", fixedVersion: null, cvss, source: "wazuh" }));
    await storeVulnerabilities(tenantId, rows(5));
    await storeVulnerabilities(tenantId, rows(9.8));
    const stored = await adminDb().select({ cvss: vulnerabilities.cvss }).from(vulnerabilities).where(eq(vulnerabilities.tenantId, tenantId));
    expect(stored).toHaveLength(1234);
    expect(new Set(stored.map((s) => Number(s.cvss)))).toEqual(new Set([9.8]));
  });
});
