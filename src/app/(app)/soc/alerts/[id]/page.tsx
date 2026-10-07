import { Sparkles } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import type { IntelMatch } from "@/db/schema";
import { AttackChips, IntelVerdict, RefLink, RiskFactors, RiskScore, SeverityBadge, StatusBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { ALERT_STATUSES, getAlert } from "@/lib/services/alerts";
import { entityLinks } from "@/lib/services/entities";
import { RESPONSE_ACTIONS, isResponseAction } from "@/lib/soar/actions";
import { describeTarget } from "@/lib/soar/response";
import { fmtDateTime, timeAgo } from "@/lib/utils";
import { AlertActions, RequestResponseDialog } from "./alert-actions";

export const metadata = { title: "Alert" };

export default async function AlertDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const ctx = await requireAccess();
  const data = /^[0-9a-f-]{36}$/i.test(id) ? await getAlert(ctx, id) : null;
  if (!data) notFound();
  const { alert: a, asset, observables, related, incident, actions } = data;
  const tenantId = a.tenantId;
  const canTriage = can(ctx, "alert:triage", tenantId);
  const matches = a.intel?.matches ?? [];
  const graph = await entityLinks(ctx, tenantId, { alertId: a.id, userName: a.userName });

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="space-y-3">
        <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">
          <Link href="/soc/alerts" className="hover:underline">Alert queue</Link> · {data.tenantName}
        </div>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 space-y-2">
            <h1 className="text-xl font-semibold tracking-tight">{a.title}</h1>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={a.severity} />
              <StatusBadge status={a.status} />
              <RiskScore score={a.riskScore} factors={a.riskFactors} />
              <IntelVerdict verdict={a.intelVerdict} />
              {graph.alert ? <Link href={`/soc/entities/${graph.alert}`} className="text-xs text-accent hover:underline">Entity graph</Link> : null}
              {incident ? (
                <Link href={`/soc/incidents/${incident.id}`} className="text-xs text-accent hover:underline">
                  On INC-{incident.ref}: {incident.title}
                </Link>
              ) : null}
            </div>
          </div>
          <div className="flex flex-wrap items-start gap-2">
            {can(ctx, "ai:use", tenantId) ? (
              <Button asChild size="sm" variant="secondary">
                <Link href={`/assistant?alert=${a.id}`}><Sparkles /> Ask AI analyst</Link>
              </Button>
            ) : null}
            {can(ctx, "response:request", tenantId) ? (
              <RequestResponseDialog
                alertId={a.id}
                tenantId={tenantId}
                assetId={a.assetId}
                assetName={asset?.name ?? null}
                identity={a.userName}
                observables={observables.map((o) => ({ type: o.type, value: o.value }))}
              />
            ) : null}
          </div>
        </div>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 rounded-lg border border-border bg-surface px-4 py-3 text-sm sm:grid-cols-3 xl:grid-cols-6">
          <Meta label="Customer">{data.tenantName}</Meta>
          <Meta label="Asset">
            {asset ? <Link href={`/assets/${asset.id}`} className="text-accent hover:underline">{asset.name}</Link> : <span className="text-faint">—</span>}
            {asset ? <span className="ml-1 text-xs text-muted">crit {asset.criticality}/5</span> : null}
          </Meta>
          <Meta label="User">
            {a.userName && graph.user ? <Link href={`/soc/entities/${graph.user}`} className="text-accent hover:underline">{a.userName}</Link> : a.userName ?? <span className="text-faint">—</span>}
          </Meta>
          <Meta label="Occurred"><span title={timeAgo(a.occurredAt)}>{fmtDateTime(a.occurredAt)}</span></Meta>
          <Meta label="Source">{a.source}{a.ruleId ? <span className="ml-1 text-xs text-muted">rule <RefLink type="rule" id={a.ruleId} label={a.ruleId} /></span> : null}</Meta>
          <Meta label="Assignee">{data.assigneeName ?? <span className="text-faint">Unassigned</span>}</Meta>
          <Meta label="Category">{a.category ?? <span className="text-faint">—</span>}</Meta>
          <Meta label="SIEM severity">{a.siemSeverity ?? <span className="text-faint">—</span>}</Meta>
          <Meta label="Ingested">{fmtDateTime(a.ingestedAt)}</Meta>
          <Meta label="ATT&CK"><AttackChips techniques={a.attackTechniques} max={6} /></Meta>
        </dl>
        {canTriage ? (
          <AlertActions
            alertId={a.id}
            tenantId={tenantId}
            status={a.status}
            statuses={ALERT_STATUSES}
            assignedToMe={a.assigneeId === ctx.principal.userId}
            hasIncident={!!incident}
            canTriage={canTriage}
            canEscalate={can(ctx, "incident:write", tenantId)}
          />
        ) : null}
      </div>

      {a.description ? <p className="max-w-4xl whitespace-pre-wrap text-sm text-muted">{a.description}</p> : null}

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="space-y-5 xl:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Threat intelligence</CardTitle>
              <span className="text-xs text-muted">{a.intel ? `Checked ${fmtDateTime(a.intel.checkedAt)}` : "Not yet checked"}</span>
            </CardHeader>
            {matches.length === 0 ? (
              <CardContent><p className="text-sm text-muted">No OpenCTI matches for this alert&apos;s observables.</p></CardContent>
            ) : (
              <div className="divide-y divide-border">
                {matches.map((m) => <IntelMatchPanel key={`${m.openctiId}:${m.observable.value}`} m={m} />)}
              </div>
            )}
          </Card>

          <Card>
            <CardHeader><CardTitle>Observables</CardTitle></CardHeader>
            {observables.length === 0 ? (
              <CardContent><p className="text-sm text-muted">No observables extracted.</p></CardContent>
            ) : (
              <Table>
                <THead>
                  <TR className="hover:bg-transparent"><TH>Type</TH><TH>Value</TH><TH>Field</TH><TH>Verdict</TH><TH className="text-right">Sightings</TH></TR>
                </THead>
                <TBody>
                  {observables.map((o) => (
                    <TR key={o.id}>
                      <TD className="text-xs text-muted">{o.type}</TD>
                      <TD className="max-w-md truncate font-mono text-xs">
                        <Link href={`/intel?q=${encodeURIComponent(o.value)}`} className="hover:text-accent">{o.value}</Link>
                      </TD>
                      <TD className="text-xs text-faint">{o.field ?? "—"}</TD>
                      <TD><IntelVerdict verdict={o.verdict} /></TD>
                      <TD className="num text-right text-xs">{o.sightings}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>

          <Card>
            <CardHeader><CardTitle>Related alerts</CardTitle><span className="text-xs text-muted">Same asset or user, 72 hours before</span></CardHeader>
            {related.length === 0 ? (
              <CardContent><p className="text-sm text-muted">No related alerts.</p></CardContent>
            ) : (
              <div className="divide-y divide-border">
                {related.map((r) => (
                  <Link key={r.id} href={`/soc/alerts/${r.id}`} className="flex items-center gap-3 px-4 py-2 hover:bg-surface-2/60">
                    <RiskScore score={r.riskScore} />
                    <SeverityBadge severity={r.severity} />
                    <span className="min-w-0 flex-1 truncate text-sm">{r.title}</span>
                    <span className="text-xs text-muted" title={fmtDateTime(r.occurredAt)}>{timeAgo(r.occurredAt)}</span>
                    <StatusBadge status={r.status} />
                  </Link>
                ))}
              </div>
            )}
          </Card>

          {a.raw != null ? (
            <Card>
              <details>
                <summary className="cursor-pointer px-4 py-3 text-[13px] font-semibold hover:bg-surface-2/60">Raw event</summary>
                <pre className="max-h-[32rem] overflow-auto border-t border-border bg-bg p-4 font-mono text-[11.5px] leading-relaxed text-muted">{JSON.stringify(a.raw, null, 2)}</pre>
              </details>
            </Card>
          ) : null}
        </div>

        <div className="space-y-5">
          <Card>
            <CardHeader><CardTitle>Risk breakdown</CardTitle></CardHeader>
            <CardContent>
              {a.riskFactors.length ? <RiskFactors factors={a.riskFactors} total={a.riskScore} /> : <p className="text-sm text-muted">No contributing factors recorded.</p>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Response actions</CardTitle><Link href="/soc/approvals" className="text-xs text-accent hover:underline">Approvals →</Link></CardHeader>
            {actions.length === 0 ? (
              <CardContent><p className="text-sm text-muted">None requested for this alert.</p></CardContent>
            ) : (
              <div className="divide-y divide-border">
                {actions.map((r) => (
                  <div key={r.id} className="px-4 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium">{isResponseAction(r.action) ? RESPONSE_ACTIONS[r.action].label : r.action}</span>
                      <StatusBadge status={r.status} />
                    </div>
                    <div className="text-xs text-muted">{describeTarget(r.target as Parameters<typeof describeTarget>[0])} · by {r.requestedByKind} · {timeAgo(r.createdAt)}</div>
                    {r.reason ? <div className="mt-0.5 text-xs text-faint">{r.reason}</div> : null}
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</dt>
      <dd className="mt-0.5 truncate">{children}</dd>
    </div>
  );
}

function IntelMatchPanel({ m }: { m: IntelMatch }) {
  const groups: [string, string[]][] = [
    ["Threat actors", m.threatActors],
    ["Intrusion sets", m.intrusionSets],
    ["Malware", m.malware],
    ["Campaigns", m.campaigns],
  ];
  return (
    <section className="space-y-3 px-4 py-3" aria-label={`Intel match for ${m.observable.value}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-mono text-sm">{m.observable.value}</div>
          <div className="text-[11px] text-muted">{m.observable.type} · {m.entityType} · <RefLink type="opencti" id={m.openctiId} label="Open in intel" /></div>
        </div>
        <IntelVerdict verdict={m.verdict} />
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs sm:grid-cols-4">
        <IntelField label="Score">{m.score ?? "—"}</IntelField>
        <IntelField label="Confidence">{m.confidence ?? "—"}</IntelField>
        <IntelField label="Source">{m.source ?? "OpenCTI"}</IntelField>
        <IntelField label="Sightings"><span className="num">{m.sightings}</span></IntelField>
        <IntelField label="First seen">{fmtDateTime(m.firstSeen)}</IntelField>
        <IntelField label="Last seen">{fmtDateTime(m.lastSeen)}</IntelField>
        <IntelField label="Markings (TLP / PAP)">
          {m.markings.length ? <span className="flex flex-wrap gap-1">{m.markings.map((k) => <Badge key={k} variant={/red/i.test(k) ? "danger" : /amber/i.test(k) ? "warn" : "outline"}>{k}</Badge>)}</span> : "—"}
        </IntelField>
        <IntelField label="Labels">
          {m.labels.length ? <span className="flex flex-wrap gap-1">{m.labels.map((l) => <Badge key={l} variant="intel">{l}</Badge>)}</span> : "—"}
        </IntelField>
      </dl>

      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
        {groups.map(([label, values]) => (
          <IntelField key={label} label={label}>
            {values.length ? <span className="flex flex-wrap gap-1">{values.map((v) => <Link key={v} href={`/intel?q=${encodeURIComponent(v)}`} className="rounded border border-border px-1.5 py-0.5 hover:border-intel hover:text-intel">{v}</Link>)}</span> : <span className="text-faint">None linked</span>}
          </IntelField>
        ))}
        <IntelField label="ATT&CK techniques">
          {m.attackPatterns.length ? (
            <span className="flex flex-wrap gap-1">
              {m.attackPatterns.map((p) => p.id
                ? <Link key={p.id} href={`/detections/attack?t=${p.id}`} className="rounded border border-border px-1.5 py-0.5 hover:border-accent hover:text-accent"><span className="font-mono">{p.id}</span> {p.name}</Link>
                : <span key={p.name} className="rounded border border-border px-1.5 py-0.5">{p.name}</span>)}
            </span>
          ) : <span className="text-faint">None linked</span>}
        </IntelField>
        <IntelField label="Related indicators">
          {m.relatedIndicators.length ? (
            <ul className="space-y-0.5">
              {m.relatedIndicators.map((r) => (
                <li key={r.id} className="truncate">
                  <RefLink type="opencti" id={r.id} label={r.name} />
                  {r.pattern ? <span className="ml-1 font-mono text-faint">{r.pattern}</span> : null}
                </li>
              ))}
            </ul>
          ) : <span className="text-faint">None</span>}
        </IntelField>
      </dl>
    </section>
  );
}

function IntelField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10.5px] font-medium uppercase tracking-wider text-faint">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}
