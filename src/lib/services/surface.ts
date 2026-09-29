import { randomBytes } from "node:crypto";
import { and, desc, eq, isNotNull, sql } from "drizzle-orm";
import { adminDb, type DbOrTx } from "@/db/client";
import {
  alerts, assets, auditLog, credentialExposures, dmarcReports, emailPostureChecks, intelFeeds, monitoredDomains, vulnerabilities,
  type IntelMatch,
} from "@/db/schema";
import { withScope } from "@/db/scope";
import { systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { admitScan, classifyObservation, emptyScanBudget, releaseScan, type ScanBudget, type ScanObservation } from "@/lib/asm/scan";
import { dedupeExposures, hibpFixture, infostealerFixture, sanitiseExposure, type StoredExposure } from "@/lib/credentials/exposure";
import { parseDmarcXml, unwrapDmarc, type DmarcAggregate } from "@/lib/email/dmarc";
import { parseDomainList } from "@/lib/email/domain";
import { matchLookalikes, type CtRecord, type WhoisRecord } from "@/lib/email/lookalike";
import { parsePosture, type DnsSnapshot } from "@/lib/email/posture";
import { filterByEntitlement } from "@/lib/intel/enrich";
import { ingestAlert } from "@/lib/pipeline/ingest";
import type { NormalisedAlert, Severity } from "@/lib/providers/types";
import { scoreVulnerability } from "@/lib/risk/engine";
import { actor, inTenant } from "./common";

export class SurfaceError extends Error {
  constructor(readonly code: "domain" | "missing" | "unverified" | "unattested" | "rate") {
    super(code);
  }
}

const surfaceBudget: ScanBudget = emptyScanBudget();

export function currentScanBudget(): ScanBudget {
  return surfaceBudget;
}

export function resetScanBudget() {
  surfaceBudget.inFlight.clear();
  surfaceBudget.used.length = 0;
}

type Who = { actorId: string | null; actorKind: "user" | "system" };

export async function rememberDomains(tx: DbOrTx, who: Who, tenantId: string, names: string[], source: "onboarding" | "settings") {
  const saved: { id: string; name: string; token: string }[] = [];
  for (const name of names) {
    const token = `blaksoc-verify=${randomBytes(8).toString("hex")}`;
    const [row] = await tx.insert(monitoredDomains).values({ tenantId, name, source, verificationToken: token }).onConflictDoNothing().returning();
    if (!row) continue;
    await audit(tx, { ...who, tenantId, action: "domain.register", targetType: "monitored_domain", targetId: row.id, detail: { name, source } });
    saved.push({ id: row.id, name: row.name, token });
  }
  return saved;
}

export async function addDomains(ctx: AccessContext, tenantId: string, raw: string) {
  let names: string[];
  try {
    names = parseDomainList(raw);
  } catch {
    throw new SurfaceError("domain");
  }
  return inTenant(ctx, "response:approve", tenantId, (tx) => rememberDomains(tx, actor(ctx), tenantId, names, "settings"));
}

export async function confirmVerification(ctx: AccessContext, tenantId: string, domainId: string, txtValues: string[]) {
  return inTenant(ctx, "response:approve", tenantId, async (tx) => {
    const [row] = await tx.select().from(monitoredDomains).where(and(eq(monitoredDomains.id, domainId), eq(monitoredDomains.tenantId, tenantId)));
    if (!row) throw new SurfaceError("missing");
    if (!txtValues.some((value) => value.includes(row.verificationToken))) return { verified: false as const };
    await tx.update(monitoredDomains).set({ verifiedAt: new Date() }).where(eq(monitoredDomains.id, row.id));
    await audit(tx, { ...actor(ctx), tenantId, action: "domain.verify", targetType: "monitored_domain", targetId: row.id, detail: { name: row.name } });
    return { verified: true as const };
  });
}

export async function checkPostureForm(ctx: AccessContext, tenantId: string, domainId: string, fields: { spf: string; dmarc: string; dkim: string; extras: string }) {
  const name = await inTenant(ctx, "response:approve", tenantId, async (tx) => {
    const [domain] = await tx.select({ name: monitoredDomains.name }).from(monitoredDomains).where(and(eq(monitoredDomains.id, domainId), eq(monitoredDomains.tenantId, tenantId)));
    if (!domain) throw new SurfaceError("missing");
    return domain.name;
  });
  return checkPosture(ctx, tenantId, domainId, dnsFromForm(name, fields.spf, fields.dmarc, fields.dkim, fields.extras));
}

export async function checkPosture(ctx: AccessContext, tenantId: string, domainId: string, dns: DnsSnapshot, now = new Date()) {
  return inTenant(ctx, "response:approve", tenantId, async (tx) => {
    const [domain] = await tx.select().from(monitoredDomains).where(and(eq(monitoredDomains.id, domainId), eq(monitoredDomains.tenantId, tenantId)));
    if (!domain) throw new SurfaceError("missing");
    const detail = parsePosture(domain.name, dns);
    await tx.insert(emailPostureChecks).values({ tenantId, domainId: domain.id, checkedAt: now, score: detail.score, detail });
    const assetId = await ensureAsset(tx, tenantId, { name: domain.name, hostname: domain.name, ips: [], exposure: "internal", kind: "domain" });
    for (const finding of detail.findings) {
      await tx.insert(vulnerabilities).values({
        tenantId, assetId, cve: finding.code, title: finding.title, packageName: domain.name, source: "email-posture", status: "open",
      }).onConflictDoUpdate({
        target: [vulnerabilities.tenantId, vulnerabilities.assetId, vulnerabilities.cve, vulnerabilities.packageName],
        set: { title: finding.title, lastSeen: now, status: "open" },
      });
    }
    return { score: detail.score, findings: detail.findings, informational: { mtaSts: detail.mtaSts.present, tlsRpt: detail.tlsRpt.present, bimi: detail.bimi.present } };
  });
}

export async function ingestDmarc(ctx: AccessContext, tenantId: string, filename: string, bytes: Buffer) {
  const summary = parseDmarcXml(unwrapDmarc(filename, bytes));
  return inTenant(ctx, "response:approve", tenantId, async (tx) => {
    const [row] = await tx.insert(dmarcReports).values({
      tenantId, domainName: summary.domain, reportId: summary.reportId, summary,
    }).onConflictDoNothing().returning({ id: dmarcReports.id });
    return { created: Boolean(row), reportId: summary.reportId, pass: summary.pass, fail: summary.fail, unknownSenders: summary.unknownSenders };
  });
}

export async function raiseLookalikes(ctx: AccessContext, tenantId: string, domainId: string, ct: CtRecord[], whois: WhoisRecord[]) {
  const domain = await inTenant(ctx, "response:approve", tenantId, async (tx) => {
    const [row] = await tx.select().from(monitoredDomains).where(and(eq(monitoredDomains.id, domainId), eq(monitoredDomains.tenantId, tenantId)));
    if (!row) throw new SurfaceError("missing");
    const prior = await tx.select({ raw: alerts.raw }).from(alerts).where(and(eq(alerts.tenantId, tenantId), eq(alerts.source, "email-posture"), eq(alerts.category, "lookalike")));
    return { name: row.name, known: prior.map((item) => String((item.raw as { domain?: string }).domain ?? "")) };
  });
  const hits = matchLookalikes(domain.name, ct, whois, domain.known);
  let created = 0;
  for (const hit of hits) {
    const description = `Lookalike ${hit.domain} registered ${hit.registeredAt ?? "on an unknown date"} via ${hit.registrar ?? "an unknown registrar"}. Certificate transparency log ${hit.ct.logId} (${hit.ct.issuer}) at ${hit.ct.loggedAt}.`;
    const result = await ingestAlert({
      tenantId,
      integrationId: null,
      source: "email-posture",
      intel: null,
      alert: normalised({
        externalId: `lookalike:${hit.domain}`,
        ruleId: "email.lookalike",
        title: `Lookalike domain ${hit.domain}`,
        description,
        category: "lookalike",
        severity: "high",
        hostname: hit.domain,
        raw: { domain: hit.domain, registeredAt: hit.registeredAt, registrar: hit.registrar, ct: hit.ct },
      }),
    });
    if (result.created) created += 1;
  }
  return { alerts: created };
}

export async function attestDomain(ctx: AccessContext, tenantId: string, domainId: string) {
  return inTenant(ctx, "response:approve", tenantId, async (tx) => {
    const [row] = await tx.select().from(monitoredDomains).where(and(eq(monitoredDomains.id, domainId), eq(monitoredDomains.tenantId, tenantId)));
    if (!row) throw new SurfaceError("missing");
    await audit(tx, { ...actor(ctx), tenantId, action: "asm.attest", targetType: "monitored_domain", targetId: row.id, detail: { name: row.name } });
    await tx.update(monitoredDomains).set({ attestedAt: new Date(), attestedBy: ctx.principal.userId }).where(eq(monitoredDomains.id, row.id));
  });
}

/** Reserved fixture profile. Every other name yields no probes and opens no sockets. */
export function observationsFor(domain: string, now: Date): ScanObservation[] {
  if (domain !== "exposed.example") return [];
  const soon = new Date(now.getTime() + 10 * 86_400_000).toISOString();
  return [
    { host: "vpn.exposed.example", ip: "203.0.113.10", port: 3389, service: "rdp", request: "connect 203.0.113.10:3389", response: "RDP negotiation", tlsNotAfter: soon },
    { host: "files.exposed.example", ip: "203.0.113.11", port: 445, service: "smb", request: "negotiate 203.0.113.11:445", response: "SMB2 dialect" },
    { host: "vpn.exposed.example", ip: "203.0.113.10", port: 443, service: "vpn", cve: "CVE-2024-0001", kev: true, request: "GET /remote/login", response: "VPN appliance", tlsNotAfter: soon },
  ];
}

export async function applyScanSystem(tenantId: string, domainId: string, observations: ScanObservation[], now = new Date()) {
  const [mark] = await adminDb().select({ id: auditLog.id, createdAt: auditLog.at }).from(auditLog).where(and(
    eq(auditLog.tenantId, tenantId), eq(auditLog.action, "asm.attest"), eq(auditLog.targetId, domainId),
  )).limit(1);
  if (!mark) throw new SurfaceError("unattested");
  const noted = await withScope(systemScope(tenantId), (tx) => shodanNote(tx, tenantId, observations));
  const pending: NormalisedAlert[] = [];
  let findings = 0;
  await withScope(systemScope(tenantId), async (tx) => {
    for (const obs of noted) {
      const classified = classifyObservation(obs, now);
      const assetId = await ensureAsset(tx, tenantId, { name: obs.host, hostname: obs.host, ips: [obs.ip], exposure: "internet", kind: "server" });
      const [asset] = await tx.select({ id: assets.id, name: assets.name, criticality: assets.criticality, exposure: assets.exposure }).from(assets).where(eq(assets.id, assetId));
      const scored = scoreVulnerability({
        cve: classified.cve, cvss: classified.kev ? 9 : null, epss: null, epssPercentile: null, kev: classified.kev, kevRansomware: false,
        kevDueDate: null, openctiThreats: [], observedExploitation: false,
        asset: { id: asset!.id, name: asset!.name, criticality: asset!.criticality, exposure: asset!.exposure },
      });
      const codes = classified.p1 ? [classified.code] : [];
      if (classified.certWindow) codes.push(`CERT-${classified.certWindow}`);
      if (!codes.length) codes.push(classified.code);
      for (const code of codes) {
        const title = code.startsWith("CERT-") ? `Certificate on ${obs.host} expires inside ${classified.certWindow} days` : classified.title;
        await tx.insert(vulnerabilities).values({
          tenantId, assetId, cve: code, title, packageName: `${obs.host}:${obs.port}`, source: "asm", status: "open",
          priorityScore: scored.score, priorityFactors: scored.factors, evidence: classified.evidence,
        }).onConflictDoUpdate({
          target: [vulnerabilities.tenantId, vulnerabilities.assetId, vulnerabilities.cve, vulnerabilities.packageName],
          set: { title, priorityScore: scored.score, priorityFactors: scored.factors, evidence: classified.evidence, lastSeen: now, status: "open" },
        });
        findings += 1;
      }
      if (classified.p1) {
        pending.push(normalised({
          externalId: `asm:${classified.code}:${obs.host}:${obs.port}`,
          ruleId: `asm.p1.${obs.service}`,
          title: classified.title,
          description: `${classified.title}. Evidence request: ${obs.request}. Evidence response: ${obs.response}.`,
          category: "p1",
          severity: "high",
          hostname: obs.host,
          raw: { evidence: classified.evidence, port: obs.port, service: obs.service, cve: classified.cve, kev: classified.kev },
        }));
      }
      if (classified.certWindow) {
        pending.push(normalised({
          externalId: `asm:cert:${classified.certWindow}:${obs.host}`,
          ruleId: `asm.cert.${classified.certWindow}`,
          title: `Certificate on ${obs.host} expires inside ${classified.certWindow} days`,
          description: `Warning at ${classified.certWindow} days. Evidence request: ${obs.request}. Evidence response: ${obs.response}.`,
          category: "certificate",
          severity: "medium",
          hostname: obs.host,
          raw: { evidence: classified.evidence, window: classified.certWindow },
        }));
      }
    }
  });
  let opened = 0;
  for (const alert of pending) {
    const result = await ingestAlert({ tenantId, integrationId: null, source: "asm", intel: null, alert });
    if (result.created) opened += 1;
  }
  return { findings, alerts: opened, attestedAt: mark.createdAt };
}

export async function runDueSurface(now = Date.now()) {
  const domains = await adminDb().select().from(monitoredDomains).where(isNotNull(monitoredDomains.attestedAt));
  let ran = 0;
  let skipped = 0;
  for (const domain of domains) {
    const obs = observationsFor(domain.name, new Date(now));
    if (!admitScan(surfaceBudget, domain.tenantId, Math.max(obs.length, 1), now)) {
      skipped += 1;
      continue;
    }
    try {
      await applyScanSystem(domain.tenantId, domain.id, obs, new Date(now));
      ran += 1;
    } catch (err) {
      if (!(err instanceof SurfaceError) || err.code !== "unattested") throw err;
      skipped += 1;
    } finally {
      releaseScan(surfaceBudget, domain.tenantId);
    }
  }
  return { ran, skipped };
}

export async function recordExposures(ctx: AccessContext, tenantId: string, domainId: string) {
  const domain = await inTenant(ctx, "response:approve", tenantId, async (tx) => {
    const [row] = await tx.select().from(monitoredDomains).where(and(eq(monitoredDomains.id, domainId), eq(monitoredDomains.tenantId, tenantId)));
    if (!row) throw new SurfaceError("missing");
    if (!row.verifiedAt) throw new SurfaceError("unverified");
    return row;
  });
  const clean = dedupeExposures([...hibpFixture(domain.name), ...infostealerFixture(domain.name)].map(sanitiseExposure));
  const kept = await inTenant(ctx, "response:approve", tenantId, (tx) => filterCommercial(tx, tenantId, clean));
  let stored = 0;
  let opened = 0;
  for (const row of kept) {
    const assetId = await inTenant(ctx, "response:approve", tenantId, (tx) => ensureAsset(tx, tenantId, {
      name: row.identity, hostname: null, ips: [], exposure: "internal", kind: "identity",
    }));
    const inserted = await inTenant(ctx, "response:approve", tenantId, async (tx) => {
      const [saved] = await tx.insert(credentialExposures).values({
        tenantId, identity: row.identity, breach: row.breach, source: row.source, observedAt: new Date(row.observedAt), dataClasses: row.dataClasses, assetId,
      }).onConflictDoNothing().returning({ id: credentialExposures.id });
      return saved;
    });
    if (!inserted) continue;
    stored += 1;
    const result = await ingestAlert({
      tenantId, integrationId: null, source: "credential-exposure", intel: null,
      alert: normalised({
        externalId: `exposure:${row.identity}:${row.breach}:${row.source}`,
        ruleId: "credential.exposure",
        title: `Credential exposure for ${row.identity}`,
        description: `${row.identity} appeared in ${row.breach} via ${row.source} on ${row.observedAt}. Data classes: ${row.dataClasses.join(", ")}. Suggested actions: reset the password, then revoke sessions. The credential exposure playbook requests both and waits for approval.`,
        category: "credential_exposure",
        severity: "high",
        userName: row.identity,
        hostname: null,
        raw: { identity: row.identity, breach: row.breach, source: row.source, observedAt: row.observedAt, dataClasses: row.dataClasses, assetId },
      }),
    });
    await withScope(systemScope(tenantId), (tx) => tx.update(alerts).set({ assetId }).where(and(eq(alerts.tenantId, tenantId), eq(alerts.externalId, `exposure:${row.identity}:${row.breach}:${row.source}`))));
    if (result.created) opened += 1;
  }
  return { stored, alerts: opened };
}

export async function domainBoard(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "vuln:read", tenantId, async (tx) => {
    const domains = await tx.select().from(monitoredDomains).where(eq(monitoredDomains.tenantId, tenantId)).orderBy(monitoredDomains.name);
    const checks = await tx.select().from(emailPostureChecks).where(eq(emailPostureChecks.tenantId, tenantId)).orderBy(desc(emailPostureChecks.checkedAt)).limit(20);
    const reports = await tx.select().from(dmarcReports).where(eq(dmarcReports.tenantId, tenantId)).orderBy(desc(dmarcReports.ingestedAt)).limit(10);
    return { domains, checks, reports };
  });
}

export function dnsFromForm(domain: string, spf: string, dmarc: string, dkim: string, extras: string): DnsSnapshot {
  const txt: DnsSnapshot["txt"] = [];
  const lines = (block: string) => block.split(/\n+/).map((line) => line.trim()).filter(Boolean);
  const spfLines = lines(spf);
  if (spfLines.length) txt.push({ name: domain, values: spfLines });
  const dmarcLines = lines(dmarc);
  if (dmarcLines.length) txt.push({ name: `_dmarc.${domain}`, values: dmarcLines });
  for (const line of lines(dkim)) {
    const splitAt = line.indexOf(" ");
    if (splitAt < 1) continue;
    txt.push({ name: line.slice(0, splitAt), values: [line.slice(splitAt + 1).trim()] });
  }
  for (const line of lines(extras)) {
    const splitAt = line.indexOf(" ");
    if (splitAt < 1) continue;
    txt.push({ name: line.slice(0, splitAt), values: [line.slice(splitAt + 1).trim()] });
  }
  return { txt };
}

async function ensureAsset(tx: DbOrTx, tenantId: string, input: { name: string; hostname: string | null; ips: string[]; exposure: "internal" | "internet"; kind: "domain" | "server" | "identity" }) {
  const [existing] = await tx.select().from(assets).where(and(eq(assets.tenantId, tenantId), eq(assets.kind, input.kind), sql`lower(${assets.name}) = ${input.name.toLowerCase()}`));
  if (existing) {
    if (input.exposure === "internet" && existing.exposure !== "internet") {
      await tx.update(assets).set({ exposure: "internet", ips: input.ips.length ? input.ips : existing.ips }).where(eq(assets.id, existing.id));
    }
    return existing.id;
  }
  const hostKey = input.hostname ? [`host:${input.hostname.toLowerCase().split(".")[0]}`] : [];
  const [row] = await tx.insert(assets).values({
    tenantId, kind: input.kind, name: input.name, hostname: input.hostname, ips: input.ips, exposure: input.exposure, dedupeKeys: hostKey,
  }).returning({ id: assets.id });
  return row!.id;
}

function normalised(partial: {
  externalId: string; ruleId: string; title: string; description: string; category: string; severity: Severity;
  hostname: string | null; userName?: string | null; raw: Record<string, unknown>;
}): NormalisedAlert {
  return {
    ...partial,
    userName: partial.userName ?? null,
    siemSeverity: null,
    occurredAt: new Date(),
    assetExternalId: null,
    attackTechniques: [],
    routingKeys: [],
  };
}

function blankMatch(source: string, value: string): IntelMatch {
  return {
    observable: { type: "user", value }, openctiId: `feed:${source}`, entityType: "exposure", verdict: "suspicious",
    score: 40, confidence: null, source, markings: [], labels: [], firstSeen: null, lastSeen: null,
    threatActors: [], intrusionSets: [], malware: [], campaigns: [], attackPatterns: [], relatedIndicators: [], sightings: 0,
  };
}

async function filterCommercial(tx: DbOrTx, tenantId: string, rows: StoredExposure[]): Promise<StoredExposure[]> {
  const commercial = rows.filter((row) => row.source !== "hibp");
  if (!commercial.length) return rows;
  const kept = await filterByEntitlement(tx, tenantId, commercial.map((row) => blankMatch(row.source, row.identity)));
  const allowed = new Set(kept.map((match) => match.source));
  return rows.filter((row) => row.source === "hibp" || allowed.has(row.source));
}

async function shodanNote(tx: DbOrTx, tenantId: string, observations: ScanObservation[]): Promise<ScanObservation[]> {
  const feeds = await tx.select().from(intelFeeds);
  const feed = feeds.find((item) => item.commercial && (item.name === "Shodan" || item.connector.createdBy === "Shodan"));
  if (!feed) return observations;
  const kept = await filterByEntitlement(tx, tenantId, [blankMatch("Shodan", observations[0]?.ip ?? "0.0.0.0")]);
  if (!kept.length) return observations;
  return observations.map((obs) => ({ ...obs, response: `${obs.response} shodan:fixture` }));
}

export type { DmarcAggregate };
