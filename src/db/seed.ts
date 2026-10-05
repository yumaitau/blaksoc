import { randomBytes, randomUUID } from "node:crypto";
import { hashPassword } from "better-auth/crypto";
import { eq, sql } from "drizzle-orm";
import { BUILTIN_ROLES } from "@/lib/auth/permissions";
import { secretAad } from "@/lib/connectors/instances";
import { encryptSecret, sha256 } from "@/lib/crypto";
import { CREDENTIAL_EXPOSURE_PLAYBOOK } from "@/lib/credentials/playbook";
import { BEC_DETECTIONS, SUSPECTED_BEC_PLAYBOOK } from "@/lib/detections/bec";
import { attackTechniques as sigmaAttack, parseSigma, runTests } from "@/lib/detections/sigma";
import { smeImportPlan } from "@/lib/detections/sme-pack";
import { env } from "@/lib/env";
import { FixtureIntelProvider } from "@/lib/intel/fixture";
import { ingestAlert } from "@/lib/pipeline/ingest";
import { syncAssets } from "@/lib/pipeline/assets";
import { eventProvider } from "@/lib/connectors/instances";
import { connectorDef } from "@/lib/connectors/registry";
import { DemoProvider } from "@/lib/providers/demo";
import { redis } from "@/lib/redis";
import { createIncidentFromAlerts } from "@/lib/services/incidents";
import { withScope } from "./scope";
import { adminDb } from "./client";
import * as s from "./schema";
import { ATTACK, CVES, FEEDS, SIGMA_RULES } from "./seed/reference";

const db = adminDb();

async function upsertUser(email: string, name: string, opts: { password?: string; breakGlass?: boolean } = {}) {
  const [existing] = await db.select().from(s.user).where(eq(s.user.email, email));
  const id = existing?.id ?? randomUUID();
  if (!existing) await db.insert(s.user).values({ id, email, name, emailVerified: true, isBreakGlass: !!opts.breakGlass });
  if (opts.password) {
    await db.delete(s.account).where(eq(s.account.userId, id));
    await db.insert(s.account).values({ id: randomUUID(), userId: id, accountId: id, providerId: "credential", password: await hashPassword(opts.password) });
  }
  return id;
}

async function assign(userId: string, roleKey: string, tenantId: string | null) {
  await db.insert(s.roleAssignments).values({ userId, roleKey, tenantId }).onConflictDoNothing();
}

async function main() {
  const demo = env().DEMO_MODE === "true";

  // ---- reference data (safe for every deployment)
  for (const r of BUILTIN_ROLES) {
    await db.insert(s.roles).values({ ...r, permissions: [...r.permissions], builtin: true }).onConflictDoUpdate({ target: s.roles.key, set: { name: r.name, description: r.description, permissions: [...r.permissions], scope: r.scope } });
  }
  for (const [id, name, tactics] of ATTACK) {
    await db.insert(s.attackTechniques).values({ id, name, tactics, parentId: id.includes(".") ? id.split(".")[0]! : null }).onConflictDoNothing();
  }
  for (const f of FEEDS) {
    await db.insert(s.intelFeeds).values({ key: f.key, name: f.name, category: f.category, license: f.license, commercial: "commercial" in f ? f.commercial : false, enabled: "enabled" in f ? f.enabled : true, connector: f.connector, notes: "notes" in f ? f.notes : null }).onConflictDoNothing();
  }
  for (const c of CVES) {
    await db.insert(s.cveIntel).values({ cve: c.cve, summary: c.summary, cvss: c.cvss, epss: c.epss, epssPercentile: c.pct, kev: c.kev, kevRansomware: !!c.ransomware, kevDueDate: c.due ?? null }).onConflictDoNothing();
  }
  for (const yaml of [...SIGMA_RULES, ...BEC_DETECTIONS.map((d) => d.yaml)]) {
    const r = parseSigma(yaml);
    const [exists] = await db.select().from(s.sigmaRules).where(eq(s.sigmaRules.sigmaId, r.id));
    if (exists) continue;
    const [row] = await db.insert(s.sigmaRules).values({ tenantId: null, sigmaId: r.id, title: r.title, description: r.description, status: r.status ?? "experimental", severity: r.level ?? "medium", logsource: r.logsource, attackTechniques: sigmaAttack(r), falsePositives: r.falsepositives ?? [], confidence: r.status === "stable" ? 75 : 50 }).returning();
    await db.insert(s.sigmaRuleVersions).values({ ruleId: row!.id, tenantId: null, version: 1, yaml, sha256: sha256(yaml), changeNote: "Initial import" });
  }
  for (const d of BEC_DETECTIONS) {
    const parsed = parseSigma(d.yaml);
    const { results, passed } = runTests(parsed, d.cases);
    if (!passed) throw new Error(`BEC rule "${parsed.title}" failed its fixture cases`);
    const [rule] = await db.select().from(s.sigmaRules).where(eq(s.sigmaRules.sigmaId, parsed.id));
    if (!rule) continue;
    const [already] = await db.select({ id: s.sigmaRuleTests.id }).from(s.sigmaRuleTests).where(eq(s.sigmaRuleTests.ruleId, rule.id)).limit(1);
    if (already) continue;
    await db.insert(s.sigmaRuleTests).values({ ruleId: rule.id, tenantId: null, version: rule.currentVersion, cases: d.cases, results, passed, ranBy: null });
  }
  for (const row of smeImportPlan()) {
    if (!row.tests.passed) throw new Error(`SME rule "${row.title}" failed its fixture cases`);
    const [exists] = await db.select().from(s.sigmaRules).where(eq(s.sigmaRules.sigmaId, row.sigmaId));
    if (!exists) {
      const [inserted] = await db.insert(s.sigmaRules).values({ tenantId: null, sigmaId: row.sigmaId, title: row.title, description: row.description, status: row.status, severity: row.severity, logsource: row.logsource, attackTechniques: row.attackTechniques, falsePositives: row.falsePositives, confidence: row.confidence, enabled: row.enabled }).returning();
      await db.insert(s.sigmaRuleVersions).values({ ruleId: inserted!.id, tenantId: null, version: 1, yaml: row.yaml, sha256: sha256(row.yaml), changeNote: "Initial import" });
    }
    const [rule] = await db.select().from(s.sigmaRules).where(eq(s.sigmaRules.sigmaId, row.sigmaId));
    if (!rule) continue;
    const [already] = await db.select({ id: s.sigmaRuleTests.id }).from(s.sigmaRuleTests).where(eq(s.sigmaRuleTests.ruleId, rule.id)).limit(1);
    if (already) continue;
    await db.insert(s.sigmaRuleTests).values({ ruleId: rule.id, tenantId: null, version: rule.currentVersion, cases: row.cases, results: row.tests.results, passed: row.tests.passed, ranBy: null });
  }

  const [pb] = await db.select().from(s.playbooks).where(eq(s.playbooks.name, "Critical malicious IP detection"));
  if (!pb) {
    await db.insert(s.playbooks).values({
      tenantId: null,
      name: "Critical malicious IP detection",
      description: "Threat-intel confirmed activity on an important asset: open an incident, notify, and request containment with human approval.",
      enabled: true,
      trigger: { event: "alert.created", conditions: [{ field: "alert.intelVerdict", op: "eq", value: "malicious" }, { field: "alert.riskScore", op: "gte", value: 60 }] },
      steps: [
        { id: "intel", action: "intel.enrich", name: "Query OpenCTI" },
        { id: "asset", action: "asset.context", name: "Check asset importance" },
        { id: "endpoint", action: "endpoint.context", name: "Gather endpoint context" },
        { id: "incident", action: "incident.create", name: "Create incident" },
        { id: "notify", action: "notify", name: "Notify analyst", params: { message: "Threat-intel confirmed activity; containment awaiting approval." } },
        { id: "isolate", action: "isolate_endpoint", name: "Isolate endpoint", when: { field: "asset.criticality", op: "gte", value: 3 } },
        { id: "disable", action: "disable_identity", name: "Disable identity", when: { field: "alert.userName", op: "neq", value: null } },
        { id: "block", action: "block_ioc", name: "Block IOC" },
        { id: "record", action: "record.note", name: "Record actions", params: { title: "Containment playbook completed" } },
      ],
    });
  }

  const [becGlobal] = await db.select().from(s.playbooks).where(eq(s.playbooks.name, SUSPECTED_BEC_PLAYBOOK.name));
  if (!becGlobal) {
    await db.insert(s.playbooks).values({ tenantId: null, ...SUSPECTED_BEC_PLAYBOOK, enabled: false });
  }
  const [credGlobal] = await db.select().from(s.playbooks).where(eq(s.playbooks.name, CREDENTIAL_EXPOSURE_PLAYBOOK.name));
  if (!credGlobal) {
    await db.insert(s.playbooks).values({ tenantId: null, ...CREDENTIAL_EXPOSURE_PLAYBOOK, enabled: false });
  }

  // ---- Yuma IT (MSSP) and break-glass administrator
  await db.insert(s.tenants).values({ slug: "yuma-it", name: "Yuma IT", kind: "mssp", sectors: ["AUSTRALIA", "INDIGENOUS_BUSINESS"] }).onConflictDoUpdate({ target: s.tenants.slug, set: { name: "Yuma IT" } });
  const bgEmail = process.env.BREAK_GLASS_EMAIL ?? "breakglass@blaksoc.local";
  const [bgExisting] = await db.select().from(s.user).where(eq(s.user.email, bgEmail));
  const bgPassword = bgExisting ? undefined : (process.env.BREAK_GLASS_PASSWORD ?? randomBytes(18).toString("base64url"));
  const bgId = await upsertUser(bgEmail, "Break-glass Administrator", { password: bgPassword, breakGlass: true });
  await assign(bgId, "platform_admin", null);
  if (bgPassword) console.log(`\nBreak-glass admin: ${bgEmail}\nPassword: ${bgPassword}\n(Enrol TOTP on first sign-in; store in the sealed break-glass envelope.)\n`);

  if (!demo) {
    console.log("seed complete (reference data only; set DEMO_MODE=true for demo tenants)");
    await redis().quit();
    process.exit(0);
  }

  // ---- demo customers
  const customers = [
    { slug: "wattle-health", name: "Wattle Health Services", sectors: ["AUSTRALIA", "HEALTHCARE", "INDIGENOUS_BUSINESS"], group: "wattle" },
    { slug: "murray-water", name: "Murray Regional Water", sectors: ["AUSTRALIA", "CRITICAL_INFRASTRUCTURE", "GOVERNMENT"], group: "murray" },
    { slug: "coastal-legal", name: "Coastal Legal Partners", sectors: ["AUSTRALIA", "SMB", "FINANCE"], group: "coastal" },
  ];
  const tenantRows: (typeof s.tenants.$inferSelect & { group: string })[] = [];
  for (const c of customers) {
    const [t] = await db.insert(s.tenants).values({ slug: c.slug, name: c.name, sectors: c.sectors, kind: "customer" }).onConflictDoUpdate({ target: s.tenants.slug, set: { name: c.name } }).returning();
    tenantRows.push({ ...t!, group: c.group });
  }
  // Demo customers already use the shared Wazuh cluster. Standard keeps that collection on.
  await db.insert(s.tenantPlans).values(tenantRows.map((t) => ({ tenantId: t.id, tier: "standard" }))).onConflictDoNothing();
  const [wattle, murray] = tenantRows;
  await db.update(s.tenants).set({ settings: { ...s.DEFAULT_TENANT_SETTINGS, sharing: { createSightings: true, attribution: "anonymised", maxTlp: "TLP:AMBER" } } }).where(eq(s.tenants.id, wattle!.id));

  const becBooks = await db.select().from(s.playbooks).where(eq(s.playbooks.name, SUSPECTED_BEC_PLAYBOOK.name));
  for (const t of tenantRows) {
    if (becBooks.some((p) => p.tenantId === t.id)) continue;
    await db.insert(s.playbooks).values({ ...SUSPECTED_BEC_PLAYBOOK, tenantId: t.id, enabled: false });
  }

  // Personas: each role explorable in DEMO_MODE via password sign-in.
  const pw = "blaksoc-demo-2026";
  const personas: [string, string, string, string | null][] = [
    ["manager@demo.blaksoc.local", "Aunty Jo Walker (SOC Manager)", "soc_manager", null],
    ["l2@demo.blaksoc.local", "Sam Nguyen (Analyst L2)", "soc_analyst_l2", null],
    ["l1@demo.blaksoc.local", "Priya Shah (Analyst L1)", "soc_analyst_l1", null],
    ["auditor@demo.blaksoc.local", "Ken Park (Auditor)", "auditor", null],
    ["wattle.admin@demo.blaksoc.local", "Wattle Health IT Admin", "customer_admin", wattle!.id],
    ["murray.security@demo.blaksoc.local", "Murray Water Security", "customer_security", murray!.id],
    ["wattle.steward@demo.blaksoc.local", "Wattle Health Data Steward", "data_steward", wattle!.id],
  ];
  const userIds: Record<string, string> = {};
  for (const [email, name, role, tenantId] of personas) {
    const id = await upsertUser(email, name, { password: pw });
    userIds[role] = id;
    await assign(id, role, tenantId);
  }
  console.log(`Demo personas (password "${pw}"): ${personas.map(([e]) => e).join(", ")}`);

  // Wattle's demo steward consented to anonymous sightings and the analyst assistant. Other demo tenants keep the most protective profile.
  await db.insert(s.dataGovernance).values({
    tenantId: wattle!.id,
    profile: {
      residencyLock: true,
      sightings: { attribution: "anonymised", maxTlp: "TLP:AMBER", consentedBy: [userIds.data_steward!], consentedAt: new Date().toISOString() },
      ai: { assistant: true, triage_summary: false },
    },
  }).onConflictDoNothing();

  // ---- integrations: shared demo "Wazuh" cluster + OpenCTI fixture, platform-owned
  const agents = tenantRows.flatMap((t, ti) =>
    ["DC01", "FS01", "WS-RECEPTION", "WS-FINANCE02", "WEB01", "VPN-GW"].map((h, i) => ({
      id: String(100 + ti * 10 + i).padStart(3, "0"),
      name: `${t.group.toUpperCase()}-${h}`,
      group: t.group,
      os: h.startsWith("WS") ? "Microsoft Windows 11 Pro" : h === "WEB01" ? "Ubuntu 24.04 LTS Server" : "Microsoft Windows Server 2022",
      ip: `10.${20 + ti}.0.${10 + i}`,
    })),
  );
  let [wz] = await db.select().from(s.integrations).where(eq(s.integrations.name, "Wazuh — AU-SYD shared cluster (demo)"));
  if (!wz) {
    [wz] = await db.insert(s.integrations).values({ tenantId: null, category: "siem", provider: "demo", name: "Wazuh — AU-SYD shared cluster (demo)", config: { agents }, status: "healthy", permissions: [] }).returning();
    await db.insert(s.integrations).values({ tenantId: null, category: "threat_intel", provider: "opencti-fixture", name: "OpenCTI (demo fixture)", config: {}, status: "healthy" });
    const [hook] = await db.insert(s.integrations).values({ tenantId: null, category: "ticketing", provider: "webhook", name: "SOC webhook (demo, disabled)", enabled: false, config: { url: "https://example.invalid/hook", events: ["incident.created"] } }).returning();
    await db.update(s.integrations).set({ secretCiphertext: encryptSecret(JSON.stringify({ signingSecret: randomBytes(24).toString("hex") }), secretAad(hook!.id)) }).where(eq(s.integrations.id, hook!.id));
    for (const t of tenantRows) await db.insert(s.integrationTenantLinks).values({ integrationId: wz!.id, tenantId: t.id, selector: { agentGroups: [t.group] } });
  }

  const provider = new DemoProvider(agents);
  const intel = new FixtureIntelProvider();
  for (const t of tenantRows) {
    const mine = (await provider.getAssets()).filter((a) => a.routingKeys.includes(`group:${t.group}`));
    const map = await withScope({ tenantIds: [t.id], platform: false }, (tx) => syncAssets(tx, t.id, wz!.id, mine));
    // Enrich inventory: criticality, exposure, identities, vulnerabilities.
    for (const [ext, assetId] of map) {
      const a = agents.find((x) => x.id === ext)!;
      const crit = /DC01|VPN-GW/.test(a.name) ? 5 : /FS01|WEB01/.test(a.name) ? 4 : 2;
      await db.update(s.assets).set({ criticality: crit, exposure: /WEB01|VPN-GW/.test(a.name) ? "internet" : "internal", owner: /WS/.test(a.name) ? "Staff" : "IT Operations", software: [{ name: "Wazuh agent", version: "4.12.0" }] }).where(eq(s.assets.id, assetId));
      const vulns = a.name.endsWith("VPN-GW") ? ["CVE-2024-3400", "CVE-2024-21762"] : a.name.endsWith("WEB01") ? ["CVE-2021-44228", "CVE-2024-6387", "CVE-2023-44487"] : a.name.endsWith("DC01") ? ["CVE-2024-38063"] : a.name.includes("WS") ? ["CVE-2023-23397", "CVE-2023-38545"] : ["CVE-2022-0778"];
      for (const cve of vulns) {
        const c = CVES.find((x) => x.cve === cve)!;
        await db.insert(s.vulnerabilities).values({ tenantId: t.id, assetId, cve, title: c.summary, cvss: c.cvss, packageName: c.summary.split(" ").slice(0, 2).join(" "), source: "wazuh" }).onConflictDoNothing();
      }
    }
    for (const [name, privileged] of [["j.nguyen.admin", true], ["svc-backup", true], ["reception", false]] as const) {
      const [exists] = await db.select().from(s.assets).where(sql`${s.assets.tenantId} = ${t.id} and ${s.assets.kind} = 'identity' and ${s.assets.name} = ${name}`);
      if (!exists) await db.insert(s.assets).values({ tenantId: t.id, kind: "identity", name, privileged, criticality: privileged ? 5 : 2, dedupeKeys: [`identity:${name}`] });
    }
  }

  // ---- alerts through the real pipeline (extraction → intel → risk → queue)
  const now = Date.now();
  for (const t of tenantRows) {
    const mine = agents.filter((a) => a.group === t.group);
    const p = new DemoProvider(mine);
    const batch = p.generate(14, new Date(now)).map((a, i) => ({ ...a, occurredAt: new Date(now - i * 3.1 * 3600_000 - Math.random() * 3600_000) }));
    const ids: string[] = [];
    for (const a of batch) {
      const r = await ingestAlert({ tenantId: t.id, integrationId: wz!.id, source: "wazuh", alert: a, intel });
      if (r.created) ids.push(r.alertId);
    }
    // Triage state variety.
    const statuses = ["TRIAGING", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"] as const;
    await withScope({ tenantIds: [t.id], platform: false }, async (tx) => {
      for (const [i, id] of ids.slice(6).entries()) await tx.update(s.alerts).set({ status: statuses[i % statuses.length], assigneeId: i % 2 ? userIds.soc_analyst_l1 : userIds.soc_analyst_l2 }).where(eq(s.alerts.id, id));
    });
    // One multi-alert incident per tenant, built from the highest-risk related alerts.
    const top = await withScope({ tenantIds: [t.id], platform: false }, (tx) => tx.select().from(s.alerts).where(eq(s.alerts.tenantId, t.id)).orderBy(sql`${s.alerts.riskScore} desc`).limit(3));
    if (top.length) {
      await withScope({ tenantIds: [t.id], platform: false }, async (tx) => {
        const inc = await createIncidentFromAlerts(null, { tenantId: t.id, alertIds: top.map((a) => a.id), ownerId: userIds.soc_analyst_l2 }, tx);
        await tx.update(s.incidents).set({ status: "INVESTIGATING", description: "Correlated threat-intel confirmed activity across multiple assets." }).where(eq(s.incidents.id, inc.id));
      });
    }
  }
  // Synthetic M365 telemetry for the Wattle demo tenant (recorded Graph fixtures, not a live tenant).
  let [m365] = await db.select().from(s.integrations).where(eq(s.integrations.name, "Microsoft 365 (demo)"));
  if (!m365) {
    const entra = connectorDef("entra");
    [m365] = await db.insert(s.integrations).values({
      tenantId: wattle!.id,
      category: "identity",
      provider: "entra",
      name: "Microsoft 365 (demo)",
      config: { azureTenantId: "00000000-0000-4000-8000-0000000000a1", mode: "fixture", subscribedSkus: ["O365_BUSINESS_ESSENTIALS"] },
      status: "healthy",
      permissions: entra?.remotePermissions ?? [],
    }).returning();
  }
  const m365Provider = eventProvider(m365!);
  const m365Assets = await m365Provider.getAssets();
  await withScope({ tenantIds: [wattle!.id], platform: false }, (tx) => syncAssets(tx, wattle!.id, m365!.id, m365Assets));
  const { alerts: m365Alerts } = await m365Provider.getAlerts({ since: new Date(Date.now() - 7 * 24 * 3600_000) });
  for (const a of m365Alerts) {
    await ingestAlert({ tenantId: wattle!.id, integrationId: m365!.id, source: "entra", alert: a, intel });
  }

  let [google] = await db.select().from(s.integrations).where(eq(s.integrations.name, "Google Workspace (demo)"));
  if (!google) {
    const workspace = connectorDef("google-workspace");
    [google] = await db.insert(s.integrations).values({
      tenantId: wattle!.id,
      category: "identity",
      provider: "google-workspace",
      name: "Google Workspace (demo)",
      config: { customerId: "my_customer", domain: "wattle.example", mode: "fixture" },
      status: "healthy",
      permissions: workspace?.remotePermissions ?? [],
    }).returning();
  }
  const googleProvider = eventProvider(google!);
  const googleAssets = await googleProvider.getAssets();
  await withScope({ tenantIds: [wattle!.id], platform: false }, (tx) => syncAssets(tx, wattle!.id, google!.id, googleAssets));
  const { alerts: googleAlerts } = await googleProvider.getAlerts({ since: new Date(Date.now() - 7 * 24 * 3600_000) });
  for (const a of googleAlerts) {
    await ingestAlert({ tenantId: wattle!.id, integrationId: google!.id, source: "google-workspace", alert: a, intel });
  }

  await db.execute(sql`update assets s set risk_score = coalesce((select max(a.risk_score) from alerts a where a.asset_id = s.id), 0)`);

  console.log("seed complete (demo)");
  await redis().quit();
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
