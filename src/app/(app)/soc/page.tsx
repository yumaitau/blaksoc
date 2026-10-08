import Link from "next/link";
import { redirect } from "next/navigation";
import { HermesBadge } from "@/components/soc/hermes-badge";
import { EmptyState, IntelVerdict, PageHeader, RiskScore, SeverityBadge, StatLink, StatusBadge } from "@/components/soc/indicators";
import { ToolCards } from "@/components/soc/tool-cards";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AccessContext } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { fatigueMetrics, socDashboard } from "@/lib/services/dashboard";
import { isHermesStaff } from "@/lib/services/hermes";
import { socTools } from "@/lib/services/soc-tools";
import { HERMES_WEEK_DAYS, hermesSwitchState, hermesWeek, latestHermesReport } from "@/lib/services/tuning";
import { runOutcome } from "@/lib/tuning/hermes-ui";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "SOC dashboard" };

/**
 * Answers, top to bottom: what is happening, what matters, who is affected,
 * what to investigate next, and what has been done. Every element links to the
 * queue or record that acts on it.
 */
export default async function SocDashboard() {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const ws = await currentWorkspace(ctx);
  const [d, tools, fatigue, hermes] = await Promise.all([socDashboard(ctx, ws.tenantIds), socTools(ctx), fatigueMetrics(ctx, ws.tenantIds), hermesSummary(ctx, ws.tenantIds)]);
  const scope = ws.tenant ? ws.tenant.name : "all customers";

  return (
    <div className="space-y-5">
      <PageHeader eyebrow="Operate" title="SOC dashboard" description={`Live posture across ${scope}. Everything here links to the work it needs.`} />

      <ToolCards tools={tools} />

      {/* What is happening / what matters */}
      <section className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <StatLink label="Critical / high-risk" value={d.counts.critical} href="/soc/alerts?minRisk=80&status=NEW,TRIAGING" tone={d.counts.critical ? "danger" : undefined} hint="Triage now" />
        <StatLink label="Awaiting triage" value={d.counts.awaitingTriage} href="/soc/alerts?status=NEW" tone={d.counts.awaitingTriage > 20 ? "warn" : undefined} hint="Open queue" />
        <StatLink label="Unassigned" value={d.counts.unassigned} href="/soc/alerts?assignee=unassigned" hint="Assign" />
        <StatLink label="Threat-intel matches" value={d.counts.intelMatched} href="/soc/alerts?intel=match" tone="intel" hint="Review matches" />
        <StatLink label="Active incidents" value={d.activeIncidents.length} href="/soc/incidents" hint="Work cases" />
        <StatLink label="Pending approvals" value={d.pendingApprovals} href="/soc/approvals" tone={d.pendingApprovals ? "warn" : "ok"} hint="Decide" />
      </section>

      <FatigueCard f={fatigue} />

      {hermes ? <HermesWeekCard h={hermes} /> : null}

      <section className="grid gap-5 xl:grid-cols-3">
        {/* What should we investigate? */}
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Investigate next</CardTitle>
            <Link href="/soc/alerts?status=NEW" className="text-xs text-accent hover:underline">Full queue →</Link>
          </CardHeader>
          <div className="divide-y divide-border">
            {d.topAlerts.length === 0 ? (
              <div className="p-4"><EmptyState title="Queue clear">No new alerts awaiting triage.</EmptyState></div>
            ) : (
              d.topAlerts.map((a) => (
                <Link key={a.id} href={`/soc/alerts/${a.id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-2/60">
                  <RiskScore score={a.riskScore} />
                  <SeverityBadge severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{a.title}</div>
                    <div className="truncate text-xs text-muted">{a.tenantName} · {a.assetName ?? "no asset"} · {timeAgo(a.occurredAt)}</div>
                  </div>
                  <IntelVerdict verdict={a.intelVerdict} />
                </Link>
              ))
            )}
          </div>
        </Card>

        {/* Who is affected? */}
        <Card>
          <CardHeader>
            <CardTitle>Customers at risk</CardTitle>
            <Link href="/soc/mssp" className="text-xs text-accent hover:underline">All customers →</Link>
          </CardHeader>
          <div className="divide-y divide-border">
            {d.customersAtRisk.map((c) => (
              <Link key={c.tenantId} href={`/soc/alerts?tenant=${c.tenantId}`} className="flex items-center justify-between gap-3 px-4 py-2.5 hover:bg-surface-2/60">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium">{c.name}</div>
                  <div className="text-xs text-muted">{c.open} open alerts</div>
                </div>
                <RiskScore score={c.risk} />
              </Link>
            ))}
          </div>
        </Card>
      </section>

      <section className="grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Active incidents</CardTitle>
            <Link href="/soc/incidents" className="text-xs text-accent hover:underline">All incidents →</Link>
          </CardHeader>
          <div className="divide-y divide-border">
            {d.activeIncidents.length === 0 ? (
              <div className="p-4"><EmptyState title="No active incidents" /></div>
            ) : (
              d.activeIncidents.map((i) => {
                const breached = i.slaDueAt && new Date(i.slaDueAt) < new Date() && i.status !== "CONTAINED";
                return (
                  <Link key={i.id} href={`/soc/incidents/${i.id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-2/60">
                    <span className="num w-16 shrink-0 font-mono text-xs text-faint">INC-{i.ref}</span>
                    <SeverityBadge severity={i.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{i.title}</div>
                      <div className="truncate text-xs text-muted">{i.tenantName} · {i.ownerName ?? "unowned"} · updated {timeAgo(i.updatedAt)}</div>
                    </div>
                    {breached ? <Badge variant="danger">SLA breached</Badge> : i.slaDueAt ? <span className="text-xs text-muted">SLA {timeAgo(i.slaDueAt)}</span> : null}
                    <StatusBadge status={i.status} />
                  </Link>
                );
              })
            )}
          </div>
        </Card>

        {/* What action has been taken? */}
        <Card>
          <CardHeader>
            <CardTitle>Containment & response</CardTitle>
            <Link href="/soc/approvals" className="text-xs text-accent hover:underline">Approvals →</Link>
          </CardHeader>
          <div className="divide-y divide-border">
            {d.containment.length === 0 ? (
              <div className="p-4 text-sm text-muted">No response actions yet.</div>
            ) : (
              d.containment.map((c) => (
                <Link key={c.id} href={c.incidentId ? `/soc/incidents/${c.incidentId}` : "/soc/approvals"} className="flex items-center justify-between gap-3 px-4 py-2.5 hover:bg-surface-2/60">
                  <div className="min-w-0">
                    <div className="truncate text-sm">{c.action.replaceAll("_", " ")}</div>
                    <div className="truncate text-xs text-muted">{c.tenantName} · by {c.requestedByKind} · {timeAgo(c.createdAt)}</div>
                  </div>
                  <StatusBadge status={c.status} />
                </Link>
              ))
            )}
          </div>
        </Card>
      </section>

      <section className="grid gap-5 lg:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardHeader><CardTitle>Threat-intel matches (24h)</CardTitle></CardHeader>
          <div className="divide-y divide-border">
            {d.intelHits.length === 0 ? <div className="p-4 text-sm text-muted">No matches in 24h.</div> : d.intelHits.map((m) => (
              <Link key={m.id} href={m.alertId ? `/soc/alerts/${m.alertId}` : "/intel"} className="block px-4 py-2 hover:bg-surface-2/60">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-xs">{m.summary.observable.value}</span>
                  <IntelVerdict verdict={m.verdict} compact />
                </div>
                <div className="truncate text-[11px] text-muted">{m.tenantName} · {[...m.summary.malware, ...m.summary.intrusionSets][0] ?? m.summary.source ?? "OpenCTI"}</div>
              </Link>
            ))}
          </div>
        </Card>

        <Card>
          <CardHeader><CardTitle>Top malicious infrastructure (7d)</CardTitle></CardHeader>
          <div className="divide-y divide-border">
            {d.topInfra.length === 0 ? <div className="p-4 text-sm text-muted">Nothing observed.</div> : d.topInfra.map((t) => (
              <Link key={`${t.type}:${t.value}`} href={`/soc/alerts?q=${encodeURIComponent(t.value)}`} className="flex items-center justify-between gap-2 px-4 py-2 hover:bg-surface-2/60">
                <div className="min-w-0">
                  <div className="truncate font-mono text-xs">{t.value}</div>
                  <div className="text-[11px] text-muted">{t.type} · {t.tenants} customer{t.tenants === 1 ? "" : "s"}</div>
                </div>
                <span className="num text-sm font-semibold">{t.hits}</span>
              </Link>
            ))}
          </div>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>ATT&CK activity (24h)</CardTitle>
            <Link href="/detections/attack" className="text-xs text-accent hover:underline">Coverage →</Link>
          </CardHeader>
          <CardContent className="space-y-2">
            {d.attackActivity.length === 0 ? <div className="text-sm text-muted">No mapped activity.</div> : d.attackActivity.map((a) => {
              const max = d.attackActivity[0]!.n;
              return (
                <Link key={a.technique} href={`/soc/alerts?technique=${a.technique}`} className="block">
                  <div className="flex justify-between text-xs"><span className="font-mono">{a.technique}</span><span className="num text-muted">{a.n}</span></div>
                  <div className="mt-1 h-1 rounded-full bg-surface-2"><div className="h-full rounded-full bg-accent" style={{ width: `${(a.n / max) * 100}%` }} /></div>
                </Link>
              );
            })}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Analyst workload</CardTitle></CardHeader>
          <div className="divide-y divide-border">
            {d.workload.length === 0 ? <div className="p-4 text-sm text-muted">No assigned alerts.</div> : d.workload.map((w) => (
              <Link key={w.userId} href={`/soc/alerts?assignee=${w.userId}`} className="flex items-center justify-between px-4 py-2 text-sm hover:bg-surface-2/60">
                <span className="truncate">{w.name}</span>
                <span className={cn("num font-semibold", w.alerts > 15 ? "text-sev-high" : "text-fg")}>{w.alerts}</span>
              </Link>
            ))}
          </div>
        </Card>
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Vulnerable critical assets</CardTitle>
            <Link href="/vulnerabilities" className="text-xs text-accent hover:underline">Patch priorities →</Link>
          </CardHeader>
          <div className="divide-y divide-border">
            {d.vulnerableCritical.length === 0 ? <div className="p-4 text-sm text-muted">No critical assets with urgent vulnerabilities.</div> : d.vulnerableCritical.map((a) => (
              <Link key={a.id} href={`/assets/${a.id}`} className="flex items-center justify-between gap-3 px-4 py-2.5 hover:bg-surface-2/60">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium">{a.name}</div>
                  <div className="text-xs text-muted">{a.tenantName} · criticality {a.criticality}/5{a.exposure === "internet" ? " · internet-facing" : ""}</div>
                </div>
                <Badge variant="danger">{a.urgent} urgent</Badge>
              </Link>
            ))}
          </div>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Emerging Australian threats</CardTitle>
            <Link href="/intel" className="text-xs text-accent hover:underline">Threat intel →</Link>
          </CardHeader>
          <div className="divide-y divide-border">
            {d.australian.length === 0 ? (
              <div className="p-4 text-sm text-muted">No advisories ingested yet. The worker pulls ACSC and CISA feeds hourly.</div>
            ) : (
              d.australian.map((a) => (
                <a key={a.id} href={a.url} target="_blank" rel="noreferrer" className="block px-4 py-2.5 hover:bg-surface-2/60">
                  <div className="truncate text-sm font-medium">{a.title}</div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
                    <span>{a.source}</span>·<span>{fmtDateTime(a.publishedAt)}</span>
                    {a.tags.map((t) => <Badge key={t} variant="accent">{t}</Badge>)}
                    {a.cves.slice(0, 3).map((c) => <Badge key={c} variant="danger">{c}</Badge>)}
                  </div>
                </a>
              ))
            )}
          </div>
        </Card>
      </section>
    </div>
  );
}

/** Hermes' week for the staff who look after it; null when it has never run and may not act (nothing to show). */
async function hermesSummary(ctx: AccessContext, tenantIds: string[]) {
  if (!isHermesStaff(ctx)) return null;
  const [week, state, report] = await Promise.all([hermesWeek(ctx, tenantIds), hermesSwitchState(), latestHermesReport()]);
  if (!state.enabled && !report && !week.actions && !week.undone) return null;
  return { week, enabled: state.enabled, report };
}

function HermesWeekCard({ h }: { h: NonNullable<Awaited<ReturnType<typeof hermesSummary>>> }) {
  const { week: w } = h;
  const stats: [string, number, string, string][] = [
    ["Alerts closed", w.closed, "/soc/alerts?hermes=closed&sort=newest", "as false positives"],
    ["Still undoable", w.inUndoWindow, "/soc/alerts?hermes=closed&status=FALSE_POSITIVE&sort=newest", "closures inside the undo window"],
    ["Noise rules created", w.noiseRules, "/soc/tuning", "moving noise to the passive lane"],
    ["Notes added", w.notes, "/soc/alerts?hermes=annotated&sort=newest", "on alert rules"],
    ["Alerts purged", w.purged, "/soc/hermes", "past the undo window"],
    ["Undone by analysts", w.undone, "/soc/hermes", "closures and rules reversed"],
  ];
  return (
    <Card className="border-hermes/40">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <HermesBadge />
          <span>this week</span>
          <Badge variant={h.enabled ? "ok" : "default"} title={h.enabled ? "“Allow Hermes to act” is on" : "“Allow Hermes to act” is off: Hermes reads and annotates only"}>{h.enabled ? "Acting" : "Off"}</Badge>
        </CardTitle>
        <Link href="/soc/hermes" className="text-xs text-accent hover:underline">Hermes actions and switch →</Link>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted">
          {h.report ? <>Last run <span className="text-fg" title={fmtDateTime(h.report.createdAt)}>{timeAgo(h.report.createdAt)}</span>: {runOutcome(h.report.stats)}</> : "Hermes has not reported a run yet."}
          {" "}Counts cover the last {HERMES_WEEK_DAYS} days.
        </p>
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
          {stats.map(([label, value, href, hint], i) => (
            <Link key={label} href={href} className="rounded-md border border-border px-3 py-2 hover:bg-surface-2/60">
              <dt className="text-[11px] uppercase tracking-wider text-faint">{label}</dt>
              <dd className={cn("num mt-1 text-2xl font-semibold", i < 2 && value ? "text-hermes" : "text-fg")}>{value.toLocaleString("en-AU")}</dd>
              <dd className="text-[11px] text-muted">{hint}</dd>
            </Link>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

const pct = (x: number | null) => (x == null ? "—" : `${Math.round(x * 100)}%`);

function duration(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 90) return `${Math.round(seconds)}s`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)}m`;
  if (seconds < 48 * 3600) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

/** Is the queue humane? Volume, how much known noise was kept out, what waits, how fast people act, how often closures were noise. */
function FatigueCard({ f }: { f: Awaited<ReturnType<typeof fatigueMetrics>> }) {
  const stats: [string, string, string, string?][] = [
    ["Alerts stored", f.stored.toLocaleString("en-AU"), "/soc/alerts?sort=newest"],
    ["Kept out as noise", pct(f.passiveShare), "/soc/alerts?lane=passive", `${f.passive.toLocaleString("en-AU")} passive`],
    ["Awaiting triage", f.awaiting.toLocaleString("en-AU"), "/soc/alerts?status=NEW"],
    ["Median time to first triage", duration(f.medianSecondsToFirstTriage), "/soc/alerts?status=NEW", "from storage to first analyst action"],
    ["False-positive rate", pct(f.falsePositiveRate), "/soc/alerts?status=FALSE_POSITIVE", `of ${f.closed.toLocaleString("en-AU")} closed`],
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle>Alert fatigue ({f.days} days)</CardTitle>
        <Link href="/soc/tuning" className="text-xs text-accent hover:underline">Noise tuning →</Link>
      </CardHeader>
      <CardContent className="grid gap-4 lg:grid-cols-[1fr_minmax(0,22rem)]">
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {stats.map(([label, value, href, hint]) => (
            <Link key={label} href={href} className="rounded-md border border-border px-3 py-2 hover:bg-surface-2/60">
              <dt className="text-[11px] uppercase tracking-wider text-faint">{label}</dt>
              <dd className="num mt-1 text-lg font-semibold">{value}</dd>
              {hint ? <dd className="text-[11px] text-muted">{hint}</dd> : null}
            </Link>
          ))}
        </dl>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-faint">Top noise rules by hits</div>
          {f.topRules.length === 0 ? <p className="mt-1 text-sm text-muted">No alerts kept out as noise.</p> : (
            <ul className="mt-1 space-y-1">
              {f.topRules.map((r) => (
                <li key={r.id} className="flex items-center justify-between gap-2 text-xs">
                  <span className="min-w-0 truncate" title={r.reason}><span className="text-muted">{r.tenantName} · {r.source}</span> <span className="font-mono">{r.ruleId}</span> · {r.reason}</span>
                  <span className="num shrink-0 font-semibold">{r.hits}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
