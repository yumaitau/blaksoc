import { and, eq, gte, inArray, ne, sql } from "drizzle-orm";
import type { Tx } from "@/db/client";
import {
  alertObservables, alerts, assetSources, assets, cveIntel, incidentAlerts, incidents, intelMatches, observables, type IntelContext,
} from "@/db/schema";
import { withScope } from "@/db/scope";
import { systemScope } from "@/lib/auth/access";
import { publish } from "@/lib/events";
import { filterByEntitlement, lookupWithCache, summariseIntel } from "@/lib/intel/enrich";
import { extractObservables, type Observable } from "@/lib/intel/observables";
import { ocsfForAlert } from "@/lib/ocsf/map";
import { NORMALIZATION_VERSION } from "@/lib/ocsf/schema";
import { logger } from "@/lib/obs/log";
import { validateOcsf } from "@/lib/ocsf/validate";
import type { IntelProvider } from "@/lib/intel/types";
import type { NormalisedAlert } from "@/lib/providers/types";
import { scoreAlert } from "@/lib/risk/engine";

export type IngestResult = { alertId: string; created: boolean; riskScore: number; intelVerdict: string };

/**
 * Wazuh (or any provider) alert → observables → OpenCTI enrichment → risk → analyst queue.
 * Network I/O (intel lookups) happens before the write transaction.
 */
export async function ingestAlert(opts: {
  tenantId: string;
  integrationId: string | null;
  source: string;
  alert: NormalisedAlert;
  intel: IntelProvider | null;
}): Promise<IngestResult> {
  const { tenantId, alert } = opts;
  const obs: Observable[] = extractObservables({ ...alert.raw, _host: alert.hostname });
  if (alert.hostname && !obs.some((o) => o.type === "hostname")) obs.push({ type: "hostname", value: alert.hostname.toLowerCase(), field: "agent.name" });
  if (alert.userName && !obs.some((o) => o.type === "user")) obs.push({ type: "user", value: alert.userName, field: "user" });

  let intelMatchesFound = opts.intel ? (await lookupWithCache(opts.intel, obs)).matches : [];

  const result = await withScope(systemScope(tenantId), async (tx) => {
    const [dupe] = await tx
      .select({ id: alerts.id, riskScore: alerts.riskScore, intelVerdict: alerts.intelVerdict })
      .from(alerts)
      .where(and(eq(alerts.tenantId, tenantId), eq(alerts.source, opts.source), eq(alerts.externalId, alert.externalId)));
    if (dupe) return { alertId: dupe.id, created: false, riskScore: dupe.riskScore, intelVerdict: dupe.intelVerdict };

    intelMatchesFound = await filterByEntitlement(tx, tenantId, intelMatchesFound);
    const intel: IntelContext | null = opts.intel ? summariseIntel(intelMatchesFound) : null;

    const asset = await resolveAsset(tx, tenantId, opts.integrationId, alert);
    const identity = alert.userName
      ? (await tx
          .select({ name: assets.name, privileged: assets.privileged })
          .from(assets)
          .where(and(eq(assets.tenantId, tenantId), eq(assets.kind, "identity"), sql`lower(${assets.name}) = lower(${alert.userName})`))
          .limit(1))[0] ?? { name: alert.userName, privileged: /admin|svc-|root|administrator/i.test(alert.userName) }
      : null;

    const cveList = obs.filter((o) => o.type === "cve").map((o) => o.value);
    const cves = cveList.length ? await tx.select().from(cveIntel).where(inArray(cveIntel.cve, cveList)) : [];

    const since = new Date(alert.occurredAt.getTime() - 24 * 3600_000);
    const [{ n: repeatCount } = { n: 0 }] = asset && alert.ruleId
      ? await tx
          .select({ n: sql<number>`count(*)::int` })
          .from(alerts)
          .where(and(eq(alerts.tenantId, tenantId), eq(alerts.assetId, asset.id), eq(alerts.ruleId, alert.ruleId), gte(alerts.occurredAt, since)))
      : [];

    const openIncidentOnAsset = asset
      ? (await tx
          .select({ id: incidents.id })
          .from(incidentAlerts)
          .innerJoin(alerts, eq(alerts.id, incidentAlerts.alertId))
          .innerJoin(incidents, eq(incidents.id, incidentAlerts.incidentId))
          .where(and(eq(alerts.assetId, asset.id), ne(incidents.status, "CLOSED")))
          .limit(1)).length > 0
      : false;

    const { score, factors } = scoreAlert({
      severity: alert.severity,
      siemSeverity: alert.siemSeverity,
      source: opts.source,
      asset,
      identity,
      intel,
      attackTechniques: alert.attackTechniques,
      repeatCount,
      cves: cves.map((c) => ({ cve: c.cve, kev: c.kev, epss: c.epss })),
      openIncidentOnAsset,
    });

    const ingestedAt = new Date();
    const ocsf = normaliseOcsf(alert, { source: opts.source, sourceEventId: alert.externalId, tenantId, ingestedAt }, obs, score);

    const [row] = await tx
      .insert(alerts)
      .values({
        tenantId,
        integrationId: opts.integrationId,
        source: opts.source,
        externalId: alert.externalId,
        ruleId: alert.ruleId,
        title: alert.title,
        description: alert.description,
        category: alert.category,
        siemSeverity: alert.siemSeverity,
        severity: alert.severity,
        riskScore: score,
        riskFactors: factors,
        assetId: asset?.id ?? null,
        userName: alert.userName,
        attackTechniques: [...new Set([...alert.attackTechniques, ...intelMatchesFound.flatMap((m) => m.attackPatterns.map((a) => a.id).filter((x): x is string => !!x))])],
        intel,
        intelVerdict: intel?.verdict ?? "unchecked",
        raw: alert.raw,
        ocsf: ocsf?.finding ?? null,
        ocsfSourceEvent: ocsf?.sourceEvent ?? null,
        normalizationVersion: ocsf ? NORMALIZATION_VERSION : null,
        occurredAt: alert.occurredAt,
        ingestedAt,
      })
      .returning({ id: alerts.id });
    const alertId = row!.id;

    for (const o of obs) {
      const verdict = intel?.matches.find((m) => m.observable.type === o.type && m.observable.value === o.value)?.verdict ?? (opts.intel ? "unknown" : "unchecked");
      const [ob] = await tx
        .insert(observables)
        .values({ tenantId, type: o.type, value: o.value, verdict, sightings: 1 })
        .onConflictDoUpdate({
          target: [observables.tenantId, observables.type, observables.value],
          set: { sightings: sql`${observables.sightings} + 1`, lastSeen: sql`now()`, verdict: sql`case when excluded.verdict in ('malicious','suspicious') then excluded.verdict else ${observables.verdict} end` },
        })
        .returning({ id: observables.id });
      await tx.insert(alertObservables).values({ tenantId, alertId, observableId: ob!.id, field: o.field ?? null }).onConflictDoNothing();
      for (const m of intel?.matches.filter((m) => m.observable.value === o.value && m.verdict !== "benign") ?? []) {
        await tx.insert(intelMatches).values({ tenantId, alertId, observableId: ob!.id, openctiId: m.openctiId, verdict: m.verdict, score: m.score, summary: m });
      }
    }

    return { alertId, created: true, riskScore: score, intelVerdict: intel?.verdict ?? "unchecked" };
  });

  if (result.created) {
    await publish({ type: "alert.created", tenantId, id: result.alertId, title: alert.title, severity: alert.severity, riskScore: result.riskScore });
  }
  return result;
}

/**
 * OCSF records for the alert, validated before they are stored. A record that fails validation
 * is dropped (and logged) rather than stored half-formed; the alert itself is never blocked.
 */
function normaliseOcsf(alert: NormalisedAlert, provenance: Parameters<typeof ocsfForAlert>[1], obs: Observable[], riskScore: number) {
  try {
    const { finding, sourceEvent } = ocsfForAlert(alert, provenance, { observables: obs, riskScore });
    const checked = validateOcsf(finding);
    if (!checked.ok) {
      logger.warn("ocsf detection finding invalid", { source: provenance.source, externalId: alert.externalId, errors: checked.errors });
      return null;
    }
    const sourceChecked = sourceEvent ? validateOcsf(sourceEvent) : null;
    if (sourceChecked && !sourceChecked.ok) logger.warn("ocsf source event invalid", { source: provenance.source, externalId: alert.externalId, errors: sourceChecked.errors });
    return { finding, sourceEvent: sourceChecked?.ok ? sourceEvent : null };
  } catch (err) {
    logger.warn("ocsf mapping failed", { source: provenance.source, externalId: alert.externalId, err });
    return null;
  }
}

async function resolveAsset(tx: Tx, tenantId: string, integrationId: string | null, alert: NormalisedAlert) {
  const cols = { id: assets.id, name: assets.name, criticality: assets.criticality, exposure: assets.exposure };
  if (integrationId && alert.assetExternalId) {
    const [hit] = await tx
      .select(cols)
      .from(assetSources)
      .innerJoin(assets, eq(assets.id, assetSources.assetId))
      .where(and(eq(assetSources.integrationId, integrationId), eq(assetSources.externalId, alert.assetExternalId)));
    if (hit) return hit;
  }
  if (alert.hostname) {
    const [hit] = await tx
      .select(cols)
      .from(assets)
      .where(and(eq(assets.tenantId, tenantId), sql`${`host:${alert.hostname.toLowerCase().split(".")[0]}`} = any(${assets.dedupeKeys})`));
    if (hit) return hit;
  }
  return null;
}
