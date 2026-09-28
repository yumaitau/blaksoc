import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, IntelVerdict, PageHeader, RiskScore, SeverityBadge, StatLink, StatusBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { requireAccess } from "@/lib/auth/session";
import { socDashboard } from "@/lib/services/dashboard";
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
  const d = await socDashboard(ctx, ws.tenantIds);
  const scope = ws.tenant ? ws.tenant.name : "all customers";

  return (
    <div className="space-y-5">
      <PageHeader eyebrow="Operate" title="SOC dashboard" description={`Live posture across ${scope}. Everything here links to the work it needs.`} />

      {/* What is happening / what matters */}
      <section className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <StatLink label="Critical / high-risk" value={d.counts.critical} href="/soc/alerts?minRisk=80&status=NEW,TRIAGING" tone={d.counts.critical ? "danger" : undefined} hint="Triage now" />
        <StatLink label="Awaiting triage" value={d.counts.awaitingTriage} href="/soc/alerts?status=NEW" tone={d.counts.awaitingTriage > 20 ? "warn" : undefined} hint="Open queue" />
        <StatLink label="Unassigned" value={d.counts.unassigned} href="/soc/alerts?assignee=unassigned" hint="Assign" />
        <StatLink label="Threat-intel matches" value={d.counts.intelMatched} href="/soc/alerts?intel=match" tone="intel" hint="Review matches" />
        <StatLink label="Active incidents" value={d.activeIncidents.length} href="/soc/incidents" hint="Work cases" />
        <StatLink label="Pending approvals" value={d.pendingApprovals} href="/soc/approvals" tone={d.pendingApprovals ? "warn" : "ok"} hint="Decide" />
      </section>

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
