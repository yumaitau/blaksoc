import { gzipSync } from "node:zlib";
import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { afterAll, describe, expect, it } from "vitest";
import { adminDb } from "@/db/client";
import { withScope } from "@/db/scope";
import {
  alerts, assets, auditLog, credentialExposures, dmarcReports, emailPostureChecks, integrations, intelFeeds, monitoredDomains, responseActions, tenantFeedEntitlements, tenants, vulnerabilities,
} from "@/db/schema";
import type { AccessContext } from "@/lib/auth/access";
import { executeResponseAction, requestResponseAction } from "@/lib/soar/response";
import {
  addDomains, applyScanSystem, attestDomain, checkPosture, confirmVerification, currentScanBudget, domainBoard, ingestDmarc, raiseLookalikes, recordExposures, resetScanBudget, runDueSurface, SurfaceError,
} from "@/lib/services/surface";
import { admitScan } from "@/lib/asm/scan";

const created: string[] = [];
const FEEDS = ["infostealer-fixture", "shodan-fixture"];

function admin(tenantId: string): AccessContext {
  return {
    principal: { userId: "surface-admin", name: "Surface Admin", email: "surface@example.invalid", isBreakGlass: false },
    isPlatform: false,
    grants: [{
      roleKey: "customer_admin",
      tenantId,
      permissions: new Set(["portal:read", "incident:read", "asset:read", "vuln:read", "report:read", "report:generate", "response:approve", "user:manage", "audit:read", "alert:read"]),
    }],
    tenantIds: [tenantId],
    tenants: [{ id: tenantId, slug: "surface", name: "Surface", kind: "customer" }],
  };
}

async function freshTenant() {
  const slug = `surface-${randomUUID().slice(0, 8)}`;
  const [row] = await adminDb().insert(tenants).values({ slug, name: "Surface Clinic", kind: "customer" }).returning();
  created.push(row!.id);
  return row!;
}

afterAll(async () => {
  if (created.length) await adminDb().delete(tenants).where(inArray(tenants.id, created));
  await adminDb().delete(intelFeeds).where(inArray(intelFeeds.key, FEEDS));
});

describe("domain posture, scanning, and credential exposure", () => {
  it("stores settings domains, posture history, idempotent DMARC, and a lookalike alert", async () => {
    const tenant = await freshTenant();
    const ctx = admin(tenant.id);
    const [added] = await addDomains(ctx, tenant.id, "river.example");
    expect(added?.token.startsWith("blaksoc-verify=")).toBe(true);
    expect(await confirmVerification(ctx, tenant.id, added!.id, ["unrelated"])).toEqual({ verified: false });
    expect(await confirmVerification(ctx, tenant.id, added!.id, [added!.token])).toEqual({ verified: true });

    const dns = {
      txt: [
        { name: "river.example", values: ["v=spf1 -all", "v=spf1 include:_spf.google.com -all"] },
        { name: "_dmarc.river.example", values: ["v=DMARC1; p=none; pct=50"] },
      ],
    };
    const first = await checkPosture(ctx, tenant.id, added!.id, dns, new Date("2026-04-01T00:00:00.000Z"));
    const second = await checkPosture(ctx, tenant.id, added!.id, dns, new Date("2026-04-02T00:00:00.000Z"));
    expect(first.findings.map((f) => f.code)).toEqual(expect.arrayContaining(["SPF-MULTIPLE", "DMARC-NONE"]));
    expect(second.score).toBe(first.score);
    const history = await adminDb().select().from(emailPostureChecks).where(eq(emailPostureChecks.tenantId, tenant.id));
    expect(history).toHaveLength(2);
    const board = await domainBoard(ctx, tenant.id);
    expect(board.checks).toHaveLength(2);
    expect(board.domains[0]?.name).toBe("river.example");
    const [vuln] = await adminDb().select().from(vulnerabilities).where(and(eq(vulnerabilities.tenantId, tenant.id), eq(vulnerabilities.cve, "SPF-MULTIPLE")));
    expect(vuln?.title).toContain("Ask your IT provider");

    const xml = Buffer.from(`<feedback><report_metadata><org_name>Google</org_name><report_id>rpt-1</report_id></report_metadata><policy_published><domain>river.example</domain></policy_published><record><row><source_ip>198.51.100.4</source_ip><count>3</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row></record></feedback>`);
    const once = await ingestDmarc(ctx, tenant.id, "agg.xml.gz", gzipSync(xml));
    const twice = await ingestDmarc(ctx, tenant.id, "agg.xml.gz", gzipSync(xml));
    expect(once).toMatchObject({ created: true, reportId: "Google:rpt-1", fail: 3, unknownSenders: 1 });
    expect(twice.created).toBe(false);
    const zipped = Buffer.concat([
      (() => {
        const data = Buffer.from(xml.toString().replace("rpt-1", "rpt-2"));
        const name = Buffer.from("report.xml");
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4);
        local.writeUInt32LE(data.length, 18);
        local.writeUInt32LE(data.length, 22);
        local.writeUInt16LE(name.length, 26);
        return Buffer.concat([local, name, data]);
      })(),
    ]);
    const zipOnce = await ingestDmarc(ctx, tenant.id, "agg.zip", zipped);
    const zipTwice = await ingestDmarc(ctx, tenant.id, "agg.zip", zipped);
    expect(zipOnce).toMatchObject({ created: true, reportId: "Google:rpt-2" });
    expect(zipTwice.created).toBe(false);
    expect(await adminDb().select().from(dmarcReports).where(eq(dmarcReports.tenantId, tenant.id))).toHaveLength(2);

    const raised = await raiseLookalikes(ctx, tenant.id, added!.id, [
      { name: "r1ver.example", loggedAt: "2026-02-02T00:00:00.000Z", issuer: "Example CA", logId: "ct-river" },
    ], [{ domain: "r1ver.example", registeredAt: "2026-02-01T00:00:00.000Z", registrar: "Example Registrar" }]);
    expect(raised.alerts).toBe(1);
    const [look] = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.category, "lookalike")));
    expect(look?.description).toContain("2026-02-01");
    expect(look?.description).toContain("ct-river");
    expect((await raiseLookalikes(ctx, tenant.id, added!.id, [
      { name: "r1ver.example", loggedAt: "2026-02-02T00:00:00.000Z", issuer: "Example CA", logId: "ct-river" },
    ], [])).alerts).toBe(0);

    const other = await freshTenant();
    const leaked = await withScope({ tenantIds: [other.id], platform: false }, (tx) => tx.select().from(monitoredDomains).where(eq(monitoredDomains.name, "river.example")));
    expect(leaked).toEqual([]);
  });

  it("refuses a scan until ownership is attested, then stores P1 alerts, cert windows, and evidence", async () => {
    const tenant = await freshTenant();
    const ctx = admin(tenant.id);
    const [added] = await addDomains(ctx, tenant.id, "scan.example");
    const obs = [
      { host: "rdp.scan.example", ip: "203.0.113.20", port: 3389, service: "rdp" as const, request: "connect 3389", response: "rdp banner", tlsNotAfter: "2026-06-21T00:00:00.000Z" },
      { host: "files.scan.example", ip: "203.0.113.21", port: 445, service: "smb" as const, request: "negotiate 445", response: "smb dialect" },
      { host: "vpn.scan.example", ip: "203.0.113.22", port: 443, service: "vpn" as const, cve: "CVE-2024-21762", kev: true, request: "GET /remote", response: "vpn login", tlsNotAfter: "2026-06-11T00:00:00.000Z" },
      { host: "soon.scan.example", ip: "203.0.113.23", port: 443, service: "https" as const, request: "GET /", response: "ok", tlsNotAfter: "2026-06-03T00:00:00.000Z" },
    ];
    const now = new Date("2026-06-01T00:00:00.000Z");
    await expect(applyScanSystem(tenant.id, added!.id, obs, now)).rejects.toBeInstanceOf(SurfaceError);
    expect(await adminDb().select().from(vulnerabilities).where(eq(vulnerabilities.tenantId, tenant.id))).toHaveLength(0);

    await attestDomain(ctx, tenant.id, added!.id);
    const attest = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenant.id), eq(auditLog.action, "asm.attest")));
    expect(attest).toHaveLength(1);
    const scan = await applyScanSystem(tenant.id, added!.id, obs, now);
    expect(scan.attestedAt.getTime()).toBeLessThanOrEqual(Date.now());
    const vulns = await adminDb().select().from(vulnerabilities).where(eq(vulnerabilities.tenantId, tenant.id));
    expect(vulns.every((row) => row.evidence?.request && row.evidence.response)).toBe(true);
    expect(vulns.map((row) => row.cve)).toEqual(expect.arrayContaining(["ASM-RDP", "ASM-SMB", "ASM-VPN", "CERT-30", "CERT-14", "CERT-3"]));
    const exposed = await adminDb().select().from(assets).where(and(eq(assets.tenantId, tenant.id), eq(assets.exposure, "internet")));
    expect(exposed.length).toBeGreaterThan(0);
    expect(vulns.find((row) => row.cve === "ASM-RDP")?.priorityFactors.some((factor) => factor.key === "exposure")).toBe(true);
    const p1 = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.category, "p1")));
    expect(p1.map((row) => row.title).sort()).toEqual(["P1: RDP is exposed on rdp.scan.example:3389", "P1: SMB is exposed on files.scan.example:445", "P1: VPN is exposed on vpn.scan.example:443"]);
    const certs = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.category, "certificate")));
    expect(certs.map((row) => row.ruleId).sort()).toEqual(["asm.cert.14", "asm.cert.3", "asm.cert.30"]);

    await adminDb().insert(intelFeeds).values({ key: "shodan-fixture", name: "Shodan", category: "scan", license: "commercial", commercial: true, connector: { createdBy: "Shodan" } }).onConflictDoNothing();
    const blocked = await applyScanSystem(tenant.id, added!.id, obs, now);
    expect(blocked.findings).toBeGreaterThan(0);
    const quiet = await adminDb().select().from(vulnerabilities).where(and(eq(vulnerabilities.tenantId, tenant.id), eq(vulnerabilities.cve, "ASM-RDP")));
    expect(quiet[0]?.evidence?.response).not.toContain("shodan:fixture");
    await adminDb().insert(tenantFeedEntitlements).values({ tenantId: tenant.id, feedKey: "shodan-fixture", allowed: true });
    await applyScanSystem(tenant.id, added!.id, obs, now);
    const enriched = await adminDb().select().from(vulnerabilities).where(and(eq(vulnerabilities.tenantId, tenant.id), eq(vulnerabilities.cve, "ASM-RDP")));
    expect(enriched[0]?.evidence?.response).toContain("shodan:fixture");
  });

  it("runs the worker scan only inside the per-tenant budget", async () => {
    const tenant = await freshTenant();
    const ctx = admin(tenant.id);
    const [added] = await addDomains(ctx, tenant.id, "exposed.example");
    await attestDomain(ctx, tenant.id, added!.id);
    resetScanBudget();
    expect(admitScan(currentScanBudget(), tenant.id, 6, Date.now())).toBe(true);
    const skipped = await runDueSurface();
    expect(skipped.skipped).toBeGreaterThanOrEqual(1);
    expect(await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.category, "p1")))).toHaveLength(0);
    resetScanBudget();
    const ran = await runDueSurface();
    expect(ran.ran).toBeGreaterThanOrEqual(1);
    const p1 = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.category, "p1")));
    expect(p1.map((row) => row.ruleId).sort()).toEqual(["asm.p1.rdp", "asm.p1.smb", "asm.p1.vpn"]);
    resetScanBudget();
  });

  it("dedupes breach rows, links the identity, and keeps commercial rows behind entitlement", async () => {
    const tenant = await freshTenant();
    const ctx = admin(tenant.id);
    const [added] = await addDomains(ctx, tenant.id, "clinic.example");
    await expect(recordExposures(ctx, tenant.id, added!.id)).rejects.toBeInstanceOf(SurfaceError);
    await confirmVerification(ctx, tenant.id, added!.id, [(await adminDb().select().from(monitoredDomains).where(eq(monitoredDomains.id, added!.id)))[0]!.verificationToken]);
    await adminDb().insert(intelFeeds).values({ key: "infostealer-fixture", name: "Infostealer Feed", category: "breach", license: "commercial", commercial: true, connector: { createdBy: "Infostealer Feed" } }).onConflictDoNothing();

    const first = await recordExposures(ctx, tenant.id, added!.id);
    expect(first.stored).toBe(1);
    const rows = await adminDb().select().from(credentialExposures).where(eq(credentialExposures.tenantId, tenant.id));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.source).toBe("hibp");
    expect(JSON.stringify(rows)).not.toContain("must-not-be-stored");
    expect(rows[0]?.dataClasses).toEqual(["email", "password-hash"]);
    const [alert] = await adminDb().select().from(alerts).where(and(eq(alerts.tenantId, tenant.id), eq(alerts.category, "credential_exposure")));
    expect(alert?.assetId).toBe(rows[0]?.assetId);
    expect(alert?.description).toContain("Suggested actions");
    const [identity] = await adminDb().select().from(assets).where(eq(assets.id, alert!.assetId!));
    expect(identity?.kind).toBe("identity");

    await adminDb().insert(tenantFeedEntitlements).values({ tenantId: tenant.id, feedKey: "infostealer-fixture", allowed: true });
    const second = await recordExposures(ctx, tenant.id, added!.id);
    expect(second.stored).toBe(1);
    expect(await adminDb().select().from(credentialExposures).where(eq(credentialExposures.tenantId, tenant.id))).toHaveLength(2);
    const third = await recordExposures(ctx, tenant.id, added!.id);
    expect(third.stored).toBe(0);
    expect(await adminDb().select().from(credentialExposures).where(eq(credentialExposures.tenantId, tenant.id))).toHaveLength(2);
  });

  it("sends Google Workspace response actions through approval and audit", async () => {
    const tenant = await freshTenant();
    await adminDb().insert(integrations).values({
      tenantId: tenant.id,
      category: "identity",
      provider: "google-workspace",
      name: "Google Workspace",
      config: { customerId: "my_customer", domain: "river.example", mode: "fixture" },
      status: "healthy",
    });
    const res = await withScope({ tenantIds: [tenant.id], platform: false }, (tx) => requestResponseAction(tx, {
      tenantId: tenant.id,
      action: "suspend_user",
      target: { identity: "ada@river.example" },
      reason: "Suspicious login",
      requestedBy: "surface-admin",
      requestedByKind: "user",
    }));
    expect(res.needsApproval).toBe(true);
    const requested = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenant.id), eq(auditLog.action, "response.request")));
    expect(requested).toHaveLength(1);
    await adminDb().update(responseActions).set({ status: "APPROVED" }).where(eq(responseActions.id, res.action.id));
    const executed = await executeResponseAction(tenant.id, res.action.id);
    expect(executed).toMatchObject({ ok: true, message: "fixture suspend_user on ada@river.example" });
    const done = await adminDb().select().from(auditLog).where(and(eq(auditLog.tenantId, tenant.id), eq(auditLog.action, "response.execute")));
    expect(done[0]?.detail).toMatchObject({ ok: true });
  });
});
