import { and, desc, eq, ilike, inArray, or, sql } from "drizzle-orm";
import { db } from "@/db/client";
import { advisories, alerts, assets, incidents, tenants, vulnerabilities } from "@/db/schema";
import { tenantsWith, type AccessContext } from "@/lib/auth/access";
import type { Permission } from "@/lib/auth/permissions";
import { AccessDenied, scoped } from "./common";

/** One line in the command palette. `external` opens in a new tab. */
export type QuickHit = { kind: "asset" | "alert" | "incident" | "cve" | "advisory"; title: string; detail: string; href: string; external?: boolean };

const PER_KIND = 6;
const likeEscape = (v: string) => v.replace(/[\\%_]/g, (c) => `\\${c}`);
const CVE = /^cve-\d{4}-\d{4,}$/i;
const INCIDENT_REF = /^(?:inc-?)?#?(\d{1,9})$/i;

/** Whether the caller holds `permission` on any tenant of the workspace, not merely somewhere. */
const canIn = (ctx: AccessContext, permission: Permission, tenantIds: readonly string[] | undefined) => tenantsWith(ctx, permission, tenantIds).length > 0;

/** A kind the caller cannot read is empty, never an error: one denied permission must not blank the palette. */
async function maybe<T>(ctx: AccessContext, permission: Permission, tenantIds: readonly string[] | undefined, fn: Parameters<typeof scoped<T[]>>[2]): Promise<T[]> {
  if (!canIn(ctx, permission, tenantIds)) return [];
  return scoped(ctx, permission, fn, tenantIds).catch((e) => {
    if (e instanceof AccessDenied) return [];
    throw e;
  });
}

/** Records matching a short query across the caller's workspace: assets, alerts, incidents, CVEs, advisories. */
export async function quickSearch(ctx: AccessContext, query: string, tenantIds?: readonly string[]): Promise<QuickHit[]> {
  const q = query.trim().slice(0, 100);
  if (q.length < 2) return [];
  const like = `%${likeEscape(q)}%`;
  const ref = INCIDENT_REF.exec(q)?.[1];

  const [assetHits, alertHits, incidentHits, cveHits, advisoryHits] = await Promise.all([
    maybe(ctx, "asset:read", tenantIds, (tx, ids) =>
      tx
        .select({ id: assets.id, name: assets.name, kind: assets.kind, os: assets.os, tenant: tenants.name })
        .from(assets)
        .innerJoin(tenants, eq(tenants.id, assets.tenantId))
        .where(and(inArray(assets.tenantId, ids), or(ilike(assets.name, like), ilike(assets.hostname, like), sql`${q} = any(${assets.ips})`)))
        .orderBy(desc(assets.riskScore), assets.name)
        .limit(PER_KIND),
    ),
    // The alert queue and its detail page are SOC tools (alert:triage), as in the navigation.
    maybe(ctx, "alert:triage", tenantIds, (tx, ids) =>
      tx
        .select({ id: alerts.id, title: alerts.title, severity: alerts.severity, status: alerts.status, tenant: tenants.name })
        .from(alerts)
        .innerJoin(tenants, eq(tenants.id, alerts.tenantId))
        .where(and(inArray(alerts.tenantId, ids), or(ilike(alerts.title, like), ilike(alerts.userName, like))))
        .orderBy(sql`${alerts.status} in ('RESOLVED','FALSE_POSITIVE')`, desc(alerts.occurredAt))
        .limit(PER_KIND),
    ),
    maybe(ctx, "incident:read", tenantIds, (tx, ids) =>
      tx
        .select({ id: incidents.id, ref: incidents.ref, title: incidents.title, status: incidents.status, tenant: tenants.name })
        .from(incidents)
        .innerJoin(tenants, eq(tenants.id, incidents.tenantId))
        .where(and(inArray(incidents.tenantId, ids), ref ? or(eq(incidents.ref, Number(ref)), ilike(incidents.title, like)) : ilike(incidents.title, like)))
        .orderBy(desc(incidents.createdAt))
        .limit(PER_KIND),
    ),
    CVE.test(q)
      ? maybe(ctx, "vuln:read", tenantIds, (tx, ids) =>
          tx
            .select({ cve: vulnerabilities.cve, n: sql<number>`count(distinct ${vulnerabilities.assetId})::int` })
            .from(vulnerabilities)
            .where(and(inArray(vulnerabilities.tenantId, ids), eq(vulnerabilities.cve, q.toUpperCase()), eq(vulnerabilities.status, "open")))
            .groupBy(vulnerabilities.cve),
        )
      : Promise.resolve([]),
    // Advisories are global public intel, shown on platform intel pages only.
    ctx.isPlatform
      ? db()
          .select({ id: advisories.id, title: advisories.title, source: advisories.source, url: advisories.url })
          .from(advisories)
          .where(or(ilike(advisories.title, like), sql`${q.toUpperCase()} = any(${advisories.cves})`))
          .orderBy(desc(advisories.publishedAt))
          .limit(PER_KIND)
      : Promise.resolve([]),
  ]);

  const cveTitle = q.toUpperCase();
  return [
    ...incidentHits.map((i): QuickHit => ({ kind: "incident", title: `INC-${i.ref} ${i.title}`, detail: `${i.status.toLowerCase()} · ${i.tenant}`, href: `/soc/incidents/${i.id}` })),
    ...assetHits.map((a): QuickHit => ({ kind: "asset", title: a.name, detail: [a.kind.replaceAll("_", " "), a.os, a.tenant].filter(Boolean).join(" · "), href: `/assets/${a.id}` })),
    ...(CVE.test(q) && canIn(ctx, "vuln:read", tenantIds) ? [{ kind: "cve" as const, title: cveTitle, detail: cveHits[0] ? `Open on ${cveHits[0].n} asset${cveHits[0].n === 1 ? "" : "s"}` : "Not open in this workspace", href: `/vulnerabilities?cve=${cveTitle}` }] : []),
    ...alertHits.map((a): QuickHit => ({ kind: "alert", title: a.title, detail: `${a.severity} · ${a.status.toLowerCase().replaceAll("_", " ")} · ${a.tenant}`, href: `/soc/alerts/${a.id}` })),
    ...advisoryHits.map((a): QuickHit => ({ kind: "advisory", title: a.title, detail: a.source, href: a.url, external: true })),
  ];
}
