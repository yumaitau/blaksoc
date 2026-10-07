import { Bot, Cpu, FileText, Sparkles, UserRound } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import type { IntelMatch } from "@/db/schema";
import { AttackChips, IntelVerdict, RefLink, RiskScore, SeverityBadge, StatusBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { SEVERITIES } from "@/lib/services/alerts";
import { COLLECTION_STATUS_LABEL } from "@/lib/dfir/sets";
import { listCollectionTargets, listCollections } from "@/lib/services/dfir";
import { formatZoned } from "@/lib/obligations/clock";
import { CLOCK_INFO } from "@/lib/obligations/model";
import { getObligation } from "@/lib/services/obligations";
import { canViewPortal } from "@/lib/services/portal";
import { getIncident, INCIDENT_STATUSES, listIncidentOwners } from "@/lib/services/incidents";
import { isResponseAction, RESPONSE_ACTIONS } from "@/lib/soar/actions";
import { describeTarget } from "@/lib/soar/response";
import { cn, fmtDateTime, fmtTime, timeAgo } from "@/lib/utils";
import { CollectionPanel } from "./collection-panel";
import { CaseForm, EvidenceForm, NoteForm, TaskList, TimelineEventForm } from "./incident-forms";

export const metadata = { title: "Incident" };

const DAY = new Intl.DateTimeFormat("en-AU", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "Australia/Sydney" });

const ORIGIN = {
  machine: { label: "Machine", icon: Cpu, dot: "border-sev-low/60 bg-sev-low/15 text-sev-low" },
  analyst: { label: "Analyst", icon: UserRound, dot: "border-ok/60 bg-ok/15 text-ok" },
  ai: { label: "AI", icon: Bot, dot: "border-intel/60 bg-intel/15 text-intel" },
} as const;

const LINK_KINDS = [
  ["asset", "Affected assets"],
  ["identity", "Identities"],
  ["observable", "Observables"],
  ["intel", "Threat intel"],
] as const;

export default async function IncidentDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const ctx = await requireAccess();
  const data = /^[0-9a-f-]{36}$/i.test(id) ? await getIncident(ctx, id) : null;
  if (!data) notFound();
  const inc = data.incident;
  const tenantId = inc.tenantId;
  const editable = can(ctx, "incident:write", tenantId);
  // When Kelpie owns this tenant's cases, status, fields, tasks and internal notes change there.
  const kelpie = data.kelpie;
  const caseEditable = editable && !kelpie.managed;
  const owners = editable ? await listIncidentOwners(ctx, tenantId) : [];
  const collectionRows = await listCollections(ctx, inc.id);
  const targets = editable ? await listCollectionTargets(ctx, tenantId) : [];
  const obligation = await getObligation(ctx, inc.id);
  const active = !["CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"].includes(inc.status);
  const breached = active && inc.slaDueAt && inc.slaDueAt.getTime() < new Date().getTime();

  // Group the timeline by Sydney calendar day, preserving chronological order.
  const days: { day: string; events: typeof data.timeline }[] = [];
  for (const e of data.timeline) {
    const day = DAY.format(e.occurredAt);
    if (days.at(-1)?.day !== day) days.push({ day, events: [] });
    days.at(-1)!.events.push(e);
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">
            <Link href="/soc/incidents" className="hover:underline">Incidents</Link> · {data.tenantName}
          </div>
          <h1 className="text-xl font-semibold tracking-tight"><span className="num mr-2 font-mono text-faint">INC-{inc.ref}</span>{inc.title}</h1>
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
            <SeverityBadge severity={inc.severity} />
            <StatusBadge status={inc.status} />
            <RiskScore score={inc.riskScore} />
            <span>Owner: {data.ownerName ?? "unowned"}</span>
            <span>· Opened {fmtDateTime(inc.createdAt)}</span>
            {inc.slaDueAt ? (
              breached ? <Badge variant="danger">SLA breached {timeAgo(inc.slaDueAt)}</Badge> : active ? <span>· SLA due {fmtDateTime(inc.slaDueAt)}</span> : null
            ) : null}
            {inc.containedAt ? <span>· Contained {fmtDateTime(inc.containedAt)}</span> : null}
            {inc.closedAt ? <span>· Closed {fmtDateTime(inc.closedAt)}</span> : null}
          </div>
          <AttackChips techniques={inc.attackTechniques} max={8} />
        </div>
        <div className="flex flex-wrap gap-2">
          {kelpie.link?.caseUrl ? (
            <Button asChild size="sm"><a href={kelpie.link.caseUrl} target="_blank" rel="noreferrer">Open in Kelpie {kelpie.link.caseNumber}</a></Button>
          ) : kelpie.managed ? (
            <Badge variant={kelpie.link?.lastError ? "danger" : "default"}>{kelpie.link?.lastError ? `Kelpie push failed: ${kelpie.link.lastError}` : "Sending to Kelpie"}</Badge>
          ) : null}
          {can(ctx, "ai:use", tenantId) ? (
            <Button asChild size="sm" variant="secondary"><Link href={`/assistant?incident=${inc.id}`}><Sparkles /> Ask AI</Link></Button>
          ) : null}
          {can(ctx, "report:generate", tenantId) ? (
            <Button asChild size="sm"><Link href={`/reports?kind=incident&incident=${inc.id}&tenant=${tenantId}`}><FileText /> Generate incident report</Link></Button>
          ) : null}
        </div>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="space-y-5 xl:col-span-2">
          <Card>
            <CardHeader><CardTitle>Case</CardTitle></CardHeader>
            <CardContent>
              {kelpie.managed ? <p className="mb-3 text-sm text-muted">This case is managed in Kelpie. Status, severity and title come back from Kelpie every minute. Tasks and internal notes live there too.</p> : null}
              <CaseForm
                incidentId={inc.id}
                initial={{
                  status: inc.status, severity: inc.severity, ownerId: inc.ownerId, description: inc.description, containment: inc.containment,
                  remediation: inc.remediation, rootCause: inc.rootCause, lessonsLearned: inc.lessonsLearned,
                }}
                statuses={INCIDENT_STATUSES}
                severities={SEVERITIES}
                owners={owners}
                canClose={can(ctx, "incident:close", tenantId)}
                editable={caseEditable}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Timeline</CardTitle>
              <div className="flex items-center gap-3">
                <span className="hidden items-center gap-3 text-[11px] text-muted sm:flex">
                  {Object.values(ORIGIN).map((o) => (
                    <span key={o.label} className="inline-flex items-center gap-1"><span className={cn("inline-flex size-4 items-center justify-center rounded-full border", o.dot)}><o.icon className="size-2.5" /></span>{o.label}</span>
                  ))}
                </span>
                {caseEditable ? <TimelineEventForm incidentId={inc.id} /> : null}
              </div>
            </CardHeader>
            <CardContent>
              {days.length === 0 ? <p className="text-sm text-muted">No events yet.</p> : (
                <ol className="space-y-5">
                  {days.map((d) => (
                    <li key={d.day}>
                      <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-faint">{d.day}</h3>
                      <ol className="relative ml-[4.25rem] border-l border-border">
                        {d.events.map((e) => {
                          const o = ORIGIN[e.origin as keyof typeof ORIGIN] ?? ORIGIN.machine;
                          return (
                            <li key={e.id} className="relative pb-4 pl-6 last:pb-0">
                              <time dateTime={e.occurredAt.toISOString()} title={fmtDateTime(e.occurredAt)} className="num absolute -left-[4.25rem] top-0.5 w-12 text-right font-mono text-xs text-muted">
                                {fmtTime(e.occurredAt)}
                              </time>
                              <span className={cn("absolute -left-[0.6875rem] top-0 inline-flex size-[1.375rem] items-center justify-center rounded-full border", o.dot)} aria-label={`${o.label} event`}>
                                <o.icon className="size-3" />
                              </span>
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-sm font-medium">{e.title}</span>
                                <Badge variant="outline">{e.category}</Badge>
                                {e.origin === "ai" ? <Badge variant="intel">AI-generated</Badge> : null}
                              </div>
                              {e.detail ? <div className="mt-0.5 whitespace-pre-wrap text-xs text-muted">{e.detail}</div> : null}
                              {e.refType && e.refId ? <div className="mt-0.5 text-xs"><TimelineRef type={e.refType} id={e.refId} /></div> : null}
                            </li>
                          );
                        })}
                      </ol>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Alerts</CardTitle><span className="num text-xs text-muted">{data.alerts.length}</span></CardHeader>
            {data.alerts.length === 0 ? <CardContent><p className="text-sm text-muted">No alerts linked.</p></CardContent> : (
              <Table>
                <THead>
                  <TR className="hover:bg-transparent"><TH>Severity</TH><TH>Risk</TH><TH>Alert</TH><TH>Asset</TH><TH>User</TH><TH>Intel</TH><TH>ATT&CK</TH><TH>Occurred</TH><TH>Status</TH></TR>
                </THead>
                <TBody>
                  {data.alerts.map((a) => (
                    <TR key={a.id}>
                      <TD><SeverityBadge severity={a.severity} /></TD>
                      <TD><RiskScore score={a.riskScore} /></TD>
                      <TD className="max-w-sm"><Link href={`/soc/alerts/${a.id}`} className="block truncate font-medium hover:text-accent">{a.title}</Link></TD>
                      <TD className="max-w-36 truncate text-xs">{a.assetName ?? <span className="text-faint">—</span>}</TD>
                      <TD className="max-w-32 truncate text-xs">{a.userName ?? <span className="text-faint">—</span>}</TD>
                      <TD><IntelVerdict verdict={a.intelVerdict} compact /></TD>
                      <TD><AttackChips techniques={a.attackTechniques} max={2} /></TD>
                      <TD className="whitespace-nowrap text-xs text-muted">{fmtDateTime(a.occurredAt)}</TD>
                      <TD><StatusBadge status={a.status} /></TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>

          <Card>
            <CardHeader><CardTitle>Notes</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {editable ? <NoteForm incidentId={inc.id} /> : null}
              {data.notes.length === 0 ? <p className="text-sm text-muted">No notes yet.</p> : (
                <ul className="space-y-3">
                  {data.notes.map((n) => (
                    <li key={n.id} className={cn("rounded-md border px-3 py-2", n.visibility === "customer" ? "border-warn/30" : "border-border")}>
                      <div className="mb-1 flex flex-wrap items-center gap-2 text-xs text-muted">
                        <span className="font-medium text-fg">{n.authorName ?? "System"}</span>
                        <span title={fmtDateTime(n.createdAt)}>{timeAgo(n.createdAt)}</span>
                        {n.visibility === "customer" ? <Badge variant="warn">Customer-visible</Badge> : <Badge>Internal</Badge>}
                        {n.aiGenerated ? <Badge variant="intel"><Bot className="size-3" /> AI-generated</Badge> : null}
                      </div>
                      <p className="whitespace-pre-wrap text-sm">{n.body}</p>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card id="collections">
            <CardHeader><CardTitle>Collections</CardTitle></CardHeader>
            <CardContent>
              <CollectionPanel
                incidentId={inc.id}
                editable={editable}
                targets={targets.map((t) => ({ id: t.id, label: t.hostname ? `${t.name} (${t.hostname})` : t.name }))}
                collections={collectionRows.map((c) => ({
                  id: c.id,
                  label: COLLECTION_STATUS_LABEL[c.status] ?? c.status,
                  detail: `${c.artifactSets.length} sets · ${c.assetIds.length} machines${c.lowBandwidth ? " · low bandwidth" : ""}`,
                  when: fmtDateTime(c.notBefore),
                }))}
              />
            </CardContent>
          </Card>

          <Card id="evidence">
            <CardHeader><CardTitle>Evidence</CardTitle>{editable ? <EvidenceForm incidentId={inc.id} /> : null}</CardHeader>
            {data.evidence.length === 0 ? <CardContent><p className="text-sm text-muted">No evidence recorded.</p></CardContent> : (
              <Table>
                <THead>
                  <TR className="hover:bg-transparent"><TH>Name</TH><TH>Kind</TH><TH>SHA-256</TH><TH>Storage</TH><TH>Collected</TH></TR>
                </THead>
                <TBody>
                  {data.evidence.map((e) => (
                    <TR key={e.id}>
                      <TD className="max-w-56">
                        <div className="truncate font-medium">{e.name}</div>
                        {e.description ? <div className="truncate text-xs text-muted">{e.description}</div> : null}
                      </TD>
                      <TD className="text-xs text-muted">{e.kind.replaceAll("_", " ")}</TD>
                      <TD className="max-w-40 truncate font-mono text-[11px]" title={e.sha256 ?? undefined}>{e.sha256 ?? <span className="text-faint">—</span>}</TD>
                      <TD className="max-w-48 truncate font-mono text-[11px]" title={e.storageUri ?? undefined}>{e.storageUri ?? <span className="text-faint">—</span>}</TD>
                      <TD className="whitespace-nowrap text-xs text-muted">{fmtDateTime(e.collectedAt)}{e.collectedBy ? ` · ${e.collectedBy}` : ""}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
        </div>

        <div className="space-y-5">
          <Card>
            <CardHeader>
              <CardTitle>Reporting clocks</CardTitle>
              {canViewPortal(ctx, tenantId) ? <Link href={`/portal/incidents/${inc.id}#obligations`} className="text-xs text-accent hover:underline">Reporting duties →</Link> : null}
            </CardHeader>
            <CardContent>
              {!obligation ? <p className="text-sm text-muted">No reporting clock started.</p> : (
                <ul className="space-y-1.5 text-sm">
                  <li>NDB assessment due {obligation.case.dueAt.toISOString().slice(0, 10)}{obligation.case.decision ? ` · ${obligation.case.decision.replaceAll("_", " ")}` : ""}</li>
                  {obligation.clocks.map((clock) => {
                    const overdue = !clock.reportedAt && clock.dueAt.getTime() < new Date().getTime();
                    return (
                      <li key={clock.id}>
                        {CLOCK_INFO[clock.kind].label}
                        <div className="text-xs text-muted">
                          Due {formatZoned(clock.dueAt, clock.timeZone)} · {clock.reportedAt ? "marked reported" : overdue ? <Badge variant="danger">Deadline passed</Badge> : "not reported"}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Response actions</CardTitle><Link href="/soc/approvals" className="text-xs text-accent hover:underline">Approvals →</Link></CardHeader>
            {data.pendingApprovals.length ? (
              <div className="border-b border-border bg-warn/5 px-4 py-2.5">
                <div className="text-xs font-medium text-warn">{data.pendingApprovals.length} awaiting approval</div>
                <ul className="mt-1 space-y-1">
                  {data.pendingApprovals.map((p) => (
                    <li key={p.id} className="text-xs">
                      <Link href="/soc/approvals" className="hover:text-accent">{p.summary}</Link>
                      <span className="text-faint"> · by {p.requestedByKind}{p.expiresAt ? ` · expires ${timeAgo(p.expiresAt)}` : ""}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            {data.actions.length === 0 ? <CardContent><p className="text-sm text-muted">No response actions yet.</p></CardContent> : (
              <div className="divide-y divide-border">
                {data.actions.map((r) => (
                  <div key={r.id} className="px-4 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium">{isResponseAction(r.action) ? RESPONSE_ACTIONS[r.action].label : r.action}</span>
                      <StatusBadge status={r.status} />
                    </div>
                    <div className="text-xs text-muted">
                      {describeTarget(r.target as Parameters<typeof describeTarget>[0])} · by {r.requestedByKind} · {timeAgo(r.createdAt)}
                      {r.destructive ? <Badge variant="danger" className="ml-1.5">Destructive</Badge> : null}
                    </div>
                    {r.reason ? <div className="mt-0.5 text-xs text-faint">{r.reason}</div> : null}
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card>
            <CardHeader><CardTitle>Tasks</CardTitle><span className="num text-xs text-muted">{data.tasks.filter((t) => t.done).length}/{data.tasks.length}</span></CardHeader>
            <CardContent><TaskList incidentId={inc.id} tasks={data.tasks} editable={caseEditable} /></CardContent>
          </Card>

          {LINK_KINDS.map(([kind, title]) => {
            const links = data.links.filter((l) => l.kind === kind);
            return (
              <Card key={kind}>
                <CardHeader><CardTitle>{title}</CardTitle><span className="num text-xs text-muted">{links.length}</span></CardHeader>
                {links.length === 0 ? <CardContent><p className="text-sm text-muted">None linked.</p></CardContent> : (
                  <ul className="divide-y divide-border">
                    {links.map((l) => <LinkRow key={l.id} kind={kind} refId={l.refId} label={l.label} data={l.data} />)}
                  </ul>
                )}
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function TimelineRef({ type, id }: { type: string; id: string }) {
  if (type === "evidence") return <a href="#evidence" className="text-accent hover:underline">evidence</a>;
  if (type === "response_action") return <Link href="/soc/approvals" className="text-accent hover:underline">response action</Link>;
  return <RefLink type={type} id={id} />;
}

function LinkRow({ kind, refId, label, data }: { kind: string; refId: string; label: string; data: unknown }) {
  const row = "block px-4 py-2 text-sm hover:bg-surface-2/60";
  if (kind === "asset") return <li><Link href={`/assets/${refId}`} className={row}>{label}</Link></li>;
  if (kind === "identity") return <li><Link href={`/soc/alerts?q=${encodeURIComponent(label)}`} className={row}>{label}</Link></li>;
  if (kind === "observable") {
    const [type] = refId.split(":");
    return (
      <li>
        <Link href={`/intel?q=${encodeURIComponent(label)}`} className={cn(row, "flex items-center justify-between gap-2")}>
          <span className="truncate font-mono text-xs">{label}</span>
          <span className="text-[11px] text-faint">{type}</span>
        </Link>
      </li>
    );
  }
  const m = data as IntelMatch | null;
  return (
    <li>
      <Link href={`/intel?q=${encodeURIComponent(refId)}`} className={row}>
        <div className="flex items-center justify-between gap-2">
          <span className="truncate font-mono text-xs">{m?.observable.value ?? label}</span>
          {m ? <IntelVerdict verdict={m.verdict} compact /> : null}
        </div>
        {m ? (
          <div className="truncate text-[11px] text-muted">
            {[...m.threatActors, ...m.intrusionSets, ...m.malware, ...m.campaigns].join(", ") || m.source || "OpenCTI"}
            {m.markings.length ? ` · ${m.markings.join(" ")}` : ""}
          </div>
        ) : null}
      </Link>
    </li>
  );
}
