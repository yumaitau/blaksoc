import { randomUUID } from "node:crypto";
import { eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { advisories, attackTechniques, sigmaRules, tenants } from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { splitTechniqueCoverage } from "@/lib/detections/advisory-coverage";
import { smeImportPlan } from "@/lib/detections/sme-pack";
import { attackCoverage } from "@/lib/services/detections";
import { coveredAttackTechniques, listAdvisories } from "@/lib/services/intel";
import { advisoryFields } from "@/worker/jobs/intel";

const created: string[] = [];
const advisoryIds: string[] = [];

function staff(tenantId: string): AccessContext {
  const permissions: Permission[] = ["detection:read"];
  return {
    principal: { userId: "sme-analyst", name: "SME Analyst", email: "sme@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{ roleKey: "soc_analyst", tenantId, permissions: new Set(permissions) }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "sme", name: "Creek Clinic", kind: "customer" }],
  };
}

afterAll(async () => {
  if (advisoryIds.length) await adminDb().delete(advisories).where(inArray(advisories.id, advisoryIds));
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
});

describe("SME pack coverage", () => {
  it("shows pack techniques on the ATT&CK view and on an ingested advisory", async () => {
    const slug = `sme-${randomUUID().slice(0, 8)}`;
    const [tenant] = await adminDb().insert(tenants).values({ slug, name: "Creek Clinic", kind: "customer" }).returning();
    created.push(tenant!.id);
    const lead = staff(tenant!.id);

    await adminDb()
      .insert(attackTechniques)
      .values([
        { id: "T1219", name: "Remote Access Software", tactics: ["command-and-control"], parentId: null },
        { id: "T1490", name: "Inhibit System Recovery", tactics: ["impact"], parentId: null },
        { id: "T1486", name: "Data Encrypted for Impact", tactics: ["impact"], parentId: null },
        { id: "T1003", name: "OS Credential Dumping", tactics: ["credential-access"], parentId: null },
        { id: "T1003.001", name: "LSASS Memory", tactics: ["credential-access"], parentId: "T1003" },
        { id: "T1190", name: "Exploit Public-Facing Application", tactics: ["initial-access"], parentId: null },
      ])
      .onConflictDoNothing();

    const plan = smeImportPlan();
    expect(plan.every((row) => row.tests.passed && row.enabled)).toBe(true);
    await adminDb().insert(sigmaRules).values(
      plan.map((row) => ({
        tenantId: tenant!.id,
        sigmaId: row.sigmaId,
        title: row.title,
        description: row.description,
        status: row.status,
        severity: row.severity,
        logsource: row.logsource,
        attackTechniques: row.attackTechniques,
        falsePositives: row.falsePositives,
        confidence: row.confidence,
        enabled: row.enabled,
      })),
    );

    const cells = await attackCoverage(lead, [tenant!.id]);
    for (const id of ["T1219", "T1490", "T1486", "T1003", "T1003.001"]) {
      expect(cells.find((cell) => cell.id === id)!.rules, id).toBeGreaterThan(0);
    }

    const text = "ACSC advisory: actors used AnyDesk and exploited FortiGate. T1190.";
    const fields = advisoryFields("acsc-advisories", "AnyDesk and FortiGate", text);
    const [row] = await adminDb()
      .insert(advisories)
      .values({
        source: "SME pack test",
        externalId: `sme-pack:${randomUUID()}`,
        title: "AnyDesk and FortiGate",
        url: "https://example.invalid/advisory",
        summary: fields.summary,
        publishedAt: new Date(),
        cves: fields.cves,
        tags: fields.tags,
        attackTechniques: fields.attackTechniques,
      })
      .returning();
    advisoryIds.push(row!.id);

    const listed = await listAdvisories(lead, { source: "SME pack test", limit: 20 });
    const saved = listed.find((item) => item.id === row!.id);
    expect(saved?.attackTechniques).toEqual(expect.arrayContaining(["T1219", "T1190"]));
    const split = splitTechniqueCoverage(saved!.attackTechniques, await coveredAttackTechniques(lead));
    expect(split.covered).toContain("T1219");
    expect(split.uncovered).toContain("T1190");
  });
});
