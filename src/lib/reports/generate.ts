import { and, desc, eq, gte, inArray, lte, ne, notInArray, sql } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { alerts, approvals, assets, cveIntel, detectionDeployments, incidentNotes, incidents, intelMatches, reports, responseActions, sigmaRules, tenants, vulnerabilities } from "@/db/schema";
import { boardSpanDays, buildBoardContent, type BoardSpan } from "./board";
import type { ReportContent, ReportSection } from "./types";

export const REPORT_KINDS = {
  daily: { label: "Daily SOC report", days: 1 },
  weekly: { label: "Weekly SOC report", days: 7 },
  monthly_exec: { label: "Monthly executive report", days: 30 },
  incident: { label: "Incident report", days: 0 },
  vulnerability: { label: "Vulnerability report", days: 30 },
  threat_intel: { label: "Threat intelligence report", days: 30 },
  essential_eight: { label: "Essential Eight evidence", days: 30 },
  detection_coverage: { label: "Detection coverage report", days: 30 },
  sla: { label: "SLA report", days: 30 },
  board_summary: { label: "Board summary", days: 30 },
} as const;
export type ReportKind = keyof typeof REPORT_KINDS;

const fmt = (d: Date | null | undefined) => (d ? d.toISOString().replace("T", " ").slice(0, 16) : "—");

/**
 * Builds report content from records only. Every section is tagged `observed` (facts from
 * telemetry and case records) or `interpretation` (analyst notes, AI drafts), so exports can
 * never blur the two.
 */
export async function buildReport(tx: Tx, tenantId: string, kind: ReportKind, opts: { incidentId?: string; end?: Date; span?: BoardSpan } = {}): Promise<ReportContent> {
  const end = opts.end ?? new Date();
  const span: BoardSpan = opts.span === "quarter" ? "quarter" : "month";
  const days = kind === "board_summary" ? boardSpanDays(span) : REPORT_KINDS[kind].days;
  const start = new Date(end.getTime() - days * 86400_000);
  const [tenant] = await tx.select().from(tenants).where(eq(tenants.id, tenantId));
  if (kind === "board_summary") return buildBoardContent(tx, { id: tenantId, name: tenant?.name ?? "Tenant" }, { start, end, span });
  const sections: ReportSection[] = [];
  const inPeriod = (col: typeof alerts.occurredAt | typeof incidents.createdAt) => and(gte(col, start), lte(col, end));

  if (kind === "incident") {
    if (!opts.incidentId) throw new Error("incident report requires incidentId");
    const [inc] = await tx.select().from(incidents).where(and(eq(incidents.id, opts.incidentId), eq(incidents.tenantId, tenantId)));
    if (!inc) throw new Error("incident not found");
    const { incidentTimeline } = await import("@/db/schema");
    const tl = await tx.select().from(incidentTimeline).where(eq(incidentTimeline.incidentId, inc.id)).orderBy(incidentTimeline.occurredAt);
    const acts = await tx.select().from(responseActions).where(eq(responseActions.incidentId, inc.id));
    const notes = await tx.select().from(incidentNotes).where(eq(incidentNotes.incidentId, inc.id)).orderBy(incidentNotes.createdAt);
    sections.push({ heading: `INC-${inc.ref}: ${inc.title}`, basis: "observed", body: `Severity ${inc.severity}. Status ${inc.status}. Opened ${fmt(inc.createdAt)}; contained ${fmt(inc.containedAt)}; closed ${fmt(inc.closedAt)}. ATT&CK: ${inc.attackTechniques.join(", ") || "none mapped"}.` });
    sections.push({ heading: "Timeline", basis: "observed", table: { columns: ["Time (UTC)", "Origin", "Event", "Detail"], rows: tl.filter((t) => t.origin !== "ai").map((t) => [fmt(t.occurredAt), t.origin, t.title, t.detail ?? ""]) } });
    sections.push({ heading: "Response actions", basis: "observed", table: { columns: ["Action", "Status", "Requested by", "Executed"], rows: acts.map((a) => [a.action, a.status, a.requestedByKind, fmt(a.executedAt)]) } });
    const analysis = [inc.rootCause && `Root cause: ${inc.rootCause}`, inc.containment && `Containment: ${inc.containment}`, inc.remediation && `Remediation: ${inc.remediation}`, inc.lessonsLearned && `Lessons learned: ${inc.lessonsLearned}`].filter(Boolean).join("\n\n");
    if (analysis) sections.push({ heading: "Analyst assessment", basis: "interpretation", author: "analyst", body: analysis });
    for (const n of notes.filter((n) => n.visibility === "customer")) sections.push({ heading: `Note ${fmt(n.createdAt)}`, basis: "interpretation", author: n.aiGenerated ? "ai" : "analyst", body: n.body });
    return { tenantName: tenant!.name, generatedAt: new Date().toISOString(), period: { start: inc.createdAt.toISOString(), end: end.toISOString() }, sections };
  }

  if (["daily", "weekly", "monthly_exec", "sla"].includes(kind)) {
    const [a] = await tx
      .select({
        total: sql<number>`count(*)::int`,
        critical: sql<number>`count(*) filter (where ${alerts.severity} = 'critical')::int`,
        high: sql<number>`count(*) filter (where ${alerts.severity} = 'high')::int`,
        fp: sql<number>`count(*) filter (where ${alerts.status} = 'FALSE_POSITIVE')::int`,
        intel: sql<number>`count(*) filter (where ${alerts.intelVerdict} = 'malicious')::int`,
      })
      .from(alerts)
      .where(and(eq(alerts.tenantId, tenantId), inPeriod(alerts.occurredAt)));
    const incs = await tx.select().from(incidents).where(and(eq(incidents.tenantId, tenantId), inPeriod(incidents.createdAt))).orderBy(desc(incidents.createdAt));
    sections.push({ heading: "Detection summary", basis: "observed", table: { columns: ["Alerts", "Critical", "High", "Threat-intel confirmed", "False positives"], rows: [[a!.total, a!.critical, a!.high, a!.intel, a!.fp]] } });
    sections.push({ heading: "Incidents", basis: "observed", table: { columns: ["Ref", "Title", "Severity", "Status", "Opened", "Contained"], rows: incs.map((i) => [`INC-${i.ref}`, i.title, i.severity, i.status, fmt(i.createdAt), fmt(i.containedAt)]) } });
    const acts = await tx.select().from(responseActions).where(and(eq(responseActions.tenantId, tenantId), gte(responseActions.createdAt, start)));
    sections.push({ heading: "Actions taken by the SOC", basis: "observed", table: { columns: ["Action", "Status", "Initiated by", "When"], rows: acts.map((x) => [x.action, x.status, x.requestedByKind, fmt(x.createdAt)]) } });

    if (kind === "sla" || kind === "monthly_exec") {
      const rows = incs.map((i) => {
        const mttc = i.containedAt ? Math.round((i.containedAt.getTime() - i.createdAt.getTime()) / 60000) : null;
        const met = i.slaDueAt ? (i.containedAt ?? new Date()) <= i.slaDueAt : null;
        return [`INC-${i.ref}`, i.severity, fmt(i.slaDueAt), mttc == null ? "open" : `${mttc} min`, met == null ? "n/a" : met ? "met" : "breached"];
      });
      sections.push({ heading: "SLA performance (time to contain)", basis: "observed", table: { columns: ["Incident", "Severity", "SLA due", "Time to contain", "SLA"], rows } });
      const [ap] = await tx.select({ n: sql<number>`count(*)::int`, med: sql<number | null>`percentile_cont(0.5) within group (order by extract(epoch from ${approvals.decidedAt} - ${approvals.createdAt}) / 60)` }).from(approvals).where(and(eq(approvals.tenantId, tenantId), gte(approvals.createdAt, start), ne(approvals.status, "PENDING")));
      sections.push({ heading: "Approval turnaround", basis: "observed", body: `${ap!.n} approval decisions; median ${ap!.med != null ? `${Math.round(ap!.med)} minutes` : "n/a"}.` });
    }
  }

  if (["vulnerability", "monthly_exec", "essential_eight"].includes(kind)) {
    const top = await tx
      .select({ cve: vulnerabilities.cve, score: sql<number>`max(${vulnerabilities.priorityScore})::int`, assets: sql<number>`count(distinct ${vulnerabilities.assetId})::int`, kev: cveIntel.kev, epss: cveIntel.epss })
      .from(vulnerabilities)
      .leftJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve))
      .where(and(eq(vulnerabilities.tenantId, tenantId), eq(vulnerabilities.status, "open")))
      .groupBy(vulnerabilities.cve, cveIntel.cve)
      .orderBy(desc(sql`2`))
      .limit(25);
    sections.push({ heading: "Patch first", basis: "observed", table: { columns: ["CVE", "Priority", "Assets", "CISA KEV", "EPSS"], rows: top.map((v) => [v.cve, v.score, v.assets, v.kev ? "yes" : "no", v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : "—"]) } });
  }

  if (kind === "essential_eight") {
    // Telemetry only. Indicative maturity is the separate self-assessment, not this table.
    const [ep] = await tx.select({ total: sql<number>`count(*)::int`, active: sql<number>`count(*) filter (where ${assets.agentStatus} = 'active')::int` }).from(assets).where(and(eq(assets.tenantId, tenantId), inArray(assets.kind, ["endpoint", "server"])));
    const [kevOpen] = await tx.select({ n: sql<number>`count(*)::int`, oldest: sql<Date | null>`min(${vulnerabilities.firstSeen})` }).from(vulnerabilities).innerJoin(cveIntel, eq(cveIntel.cve, vulnerabilities.cve)).where(and(eq(vulnerabilities.tenantId, tenantId), eq(vulnerabilities.status, "open"), eq(cveIntel.kev, true)));
    const [mfa] = await tx.select({ n: sql<number>`count(*)::int` }).from(alerts).where(and(eq(alerts.tenantId, tenantId), inPeriod(alerts.occurredAt), sql`${alerts.attackTechniques} && array['T1110','T1110.001','T1110.003','T1078']`));
    const [macro] = await tx.select({ n: sql<number>`count(*)::int` }).from(alerts).where(and(eq(alerts.tenantId, tenantId), inPeriod(alerts.occurredAt), sql`${alerts.attackTechniques} && array['T1566.001','T1204.002','T1137']`));
    const [appctl] = await tx.select({ n: sql<number>`count(*)::int` }).from(alerts).where(and(eq(alerts.tenantId, tenantId), inPeriod(alerts.occurredAt), sql`${alerts.attackTechniques} && array['T1059','T1059.001','T1204','T1218']`));
    sections.push({
      heading: "Essential Eight — supporting telemetry",
      basis: "observed",
      table: {
        columns: ["Strategy", "Evidence from blakSOC", "Value"],
        rows: [
          ["Patch applications / operating systems", "Open CISA KEV vulnerabilities (oldest first seen)", `${kevOpen!.n} (${fmt(kevOpen!.oldest)})`],
          ["Multi-factor authentication", "Credential-attack detections this period (T1110/T1078)", mfa!.n],
          ["Configure Microsoft Office macro settings", "Macro / user-execution detections (T1566.001/T1204.002/T1137)", macro!.n],
          ["Application control", "Script/LOLBin execution detections (T1059/T1204/T1218)", appctl!.n],
          ["Regular backups / restrict admin privileges / user app hardening", "Not measurable from current telemetry", "requires evidence upload"],
          ["Endpoint visibility (supporting)", "Endpoints reporting to SIEM", `${ep!.active}/${ep!.total}`],
        ],
      },
    });
    sections.push({ heading: "Scope note", basis: "interpretation", author: "system", body: "This table is supporting telemetry. Indicative maturity is the Essential Eight self-assessment. That self-assessment is not an ACSC-endorsed audit." });
  }

  if (kind === "threat_intel" || kind === "monthly_exec" || kind === "weekly") {
    const m = await tx.select({ summary: intelMatches.summary, matchedAt: intelMatches.matchedAt }).from(intelMatches).where(and(eq(intelMatches.tenantId, tenantId), gte(intelMatches.matchedAt, start))).orderBy(desc(intelMatches.matchedAt)).limit(50);
    sections.push({ heading: "Threat intelligence observed in your environment", basis: "observed", table: { columns: ["Indicator", "Verdict", "Source", "Associations", "Seen"], rows: m.map((x) => [x.summary.observable.value, x.summary.verdict, x.summary.source ?? "OpenCTI", [...x.summary.malware, ...x.summary.intrusionSets, ...x.summary.threatActors].slice(0, 3).join(", "), fmt(x.matchedAt)]) } });
  }

  if (kind === "weekly") {
    const [seen] = await tx.select({ n: sql<number>`count(*)::int` }).from(assets).where(and(eq(assets.tenantId, tenantId), inArray(assets.kind, ["endpoint", "server"]), gte(assets.lastSeen, start)));
    const [openHealth] = await tx.select({ n: sql<number>`count(*)::int` }).from(alerts).where(and(eq(alerts.tenantId, tenantId), eq(alerts.source, "health"), notInArray(alerts.status, ["RESOLVED", "FALSE_POSITIVE"])));
    sections.push({ heading: "Coverage", basis: "observed", body: `${seen?.n ?? 0} endpoints seen this week. ${openHealth?.n ?? 0} open health alerts.` });
  }

  if (kind === "detection_coverage") {
    const deployed = await tx.select({ title: sigmaRules.title, techniques: sigmaRules.attackTechniques, version: detectionDeployments.version, lastRunAt: detectionDeployments.lastRunAt, hits: detectionDeployments.lastHitCount }).from(detectionDeployments).innerJoin(sigmaRules, eq(sigmaRules.id, detectionDeployments.ruleId)).where(and(eq(detectionDeployments.tenantId, tenantId), eq(detectionDeployments.status, "active")));
    sections.push({ heading: "Deployed detections", basis: "observed", table: { columns: ["Rule", "ATT&CK", "Version", "Last run", "Last hits"], rows: deployed.map((d) => [d.title, d.techniques.join(", "), d.version, fmt(d.lastRunAt), d.hits ?? "—"]) } });
    const techs = new Set(deployed.flatMap((d) => d.techniques.map((t) => t.split(".")[0]!)));
    sections.push({ heading: "Coverage", basis: "observed", body: `${techs.size} distinct ATT&CK techniques covered by deployed detections.` });
  }

  return { tenantName: tenant!.name, generatedAt: new Date().toISOString(), period: { start: start.toISOString(), end: end.toISOString() }, sections };
}

export async function saveReport(tx: Tx, tenantId: string, kind: ReportKind, content: ReportContent, generatedBy: string | null) {
  const [r] = await tx
    .insert(reports)
    .values({ tenantId, kind, title: kind === "board_summary" ? `${REPORT_KINDS[kind].label}: ${content.tenantName}` : `${REPORT_KINDS[kind].label} — ${content.tenantName}`, periodStart: new Date(content.period.start), periodEnd: new Date(content.period.end), content, generatedBy })
    .returning();
  return r!;
}
