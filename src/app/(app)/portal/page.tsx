import { ExternalLink } from "lucide-react";
import Link from "next/link";
import { EmptyState, PageHeader, riskTone, SeverityBadge, StatLink, StatusBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { canViewPortal, portalOverview } from "@/lib/services/portal";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Security overview" };

type Overview = NonNullable<Awaited<ReturnType<typeof portalOverview>>>;

function posture(o: Overview) {
  const r = o.overallRisk;
  const level = r >= 80 ? "critical" : r >= 60 ? "elevated" : r >= 40 ? "moderate" : "low";
  const topIncident = o.activeIncidents[0];
  const topVuln = o.topVulns[0];
  let driver: string;
  if (topIncident && topIncident.riskScore === r) driver = `The main driver is an active incident (INC-${topIncident.ref}) that the SOC is working on.`;
  else if (topVuln && topVuln.priority === r)
    driver = topVuln.kev
      ? `The main driver is ${topVuln.cve}, a weakness attackers are actively exploiting, present on ${topVuln.affectedAssets} of your systems.`
      : `The main driver is unpatched software (${topVuln.cve}) on ${topVuln.affectedAssets} of your systems.`;
  else if (o.alertStats.open) driver = `The main driver is ${o.alertStats.open} detection${o.alertStats.open === 1 ? "" : "s"} still being reviewed by the SOC.`;
  else driver = "No open detections, incidents or urgent vulnerabilities.";
  return { level, driver };
}

const ACTION_LABEL: Record<string, string> = {
  isolate_endpoint: "Isolated a device from the network",
  disable_identity: "Disabled a user account",
  block_ioc: "Blocked malicious infrastructure",
  unisolate_endpoint: "Reconnected a device",
  enable_identity: "Re-enabled a user account",
  reset_password: "Reset a password",
};

const PRIORITY_VARIANT = { urgent: "danger", high: "warn", routine: "default" } as const;

/**
 * Customer portal: plain-English answers to "are we safe, what is the SOC doing,
 * and what do we need to do". No raw events or scoring internals.
 */
export default async function PortalPage() {
  const ctx = await requireAccess();
  const ws = await currentWorkspace(ctx);
  const tenant =
    (ws.tenant?.kind === "customer" && canViewPortal(ctx, ws.tenant.id) ? ws.tenant : null) ??
    ctx.tenants.find((t) => t.kind === "customer" && canViewPortal(ctx, t.id));
  if (!tenant) {
    return (
      <div>
        <PageHeader title="Security overview" />
        <EmptyState title="No organisation to show">Your account is not linked to a customer organisation yet.</EmptyState>
      </div>
    );
  }
  const o = await portalOverview(ctx, tenant.id);
  if (!o) return <EmptyState title="Organisation not found" />;

  const p = posture(o);
  const canAssets = can(ctx, "asset:read", tenant.id);
  const canApprove = can(ctx, "response:approve", tenant.id);
  const recs = o.recommendations.filter((r) => (canAssets || !r.href.startsWith("/assets")) && (canApprove || r.href !== "/soc/approvals"));
  const coverage = o.endpoints.total ? Math.round((o.endpoints.online / o.endpoints.total) * 100) : 0;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={ctx.isPlatform ? "Customer portal preview" : "Your organisation"}
        title={`${o.tenant.name}: security overview`}
        description={ctx.isPlatform ? "This is what the customer sees. Switch customer with the workspace selector." : "A plain-English summary of your security, what the SOC is doing about it, and what we need from you."}
        actions={
          <Link href="/reports" className="text-sm text-accent hover:underline">
            {o.latestReport ? `Latest report: ${o.latestReport.title} →` : "Reports →"}
          </Link>
        }
      />

      {/* Security posture */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-6">
          <div className="text-center">
            <div className={cn("num text-4xl font-bold", riskTone(o.overallRisk))}>{o.overallRisk}</div>
            <div className="text-[11px] uppercase tracking-wider text-faint">Risk / 100</div>
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-base font-semibold">
              Your current security risk is <span className={riskTone(o.overallRisk)}>{p.level}</span>.
            </div>
            <p className="mt-1 max-w-3xl text-sm text-muted">
              {p.driver} In the last 30 days the SOC reviewed {o.alertStats.last30} detection{o.alertStats.last30 === 1 ? "" : "s"} and closed {o.alertStats.closed30}.
            </p>
          </div>
        </CardContent>
      </Card>

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatLink label="Active incidents" value={o.activeIncidents.length} href="/soc/incidents" tone={o.activeIncidents.length ? "danger" : "ok"} hint="View incidents" />
        <StatLink label="Actively exploited weaknesses" value={o.kevCves} href="/vulnerabilities?kev=1" tone={o.kevCves ? "danger" : "ok"} hint="Patch first" />
        <StatLink label="Protected endpoints" value={`${o.endpoints.online}/${o.endpoints.total}`} href={canAssets ? "/assets?kind=endpoint" : "/portal"} tone={o.endpoints.offline ? "warn" : "ok"} hint={`${coverage}% reporting`} />
        <StatLink label="Awaiting your approval" value={o.pendingApprovals} href={canApprove ? "/soc/approvals" : "/portal"} tone={o.pendingApprovals ? "warn" : "ok"} hint={canApprove ? "Decide" : "Contact your administrator"} />
      </section>

      <section className="grid gap-5 xl:grid-cols-3">
        {/* Recommendations */}
        <Card className="xl:col-span-2">
          <CardHeader><CardTitle>What we recommend</CardTitle></CardHeader>
          <div className="divide-y divide-border">
            {recs.length === 0 ? (
              <div className="p-4 text-sm text-muted">Nothing needs your attention right now.</div>
            ) : (
              recs.map((r, i) => (
                <Link key={i} href={r.href} className="flex items-start gap-3 px-4 py-2.5 hover:bg-surface-2/60">
                  <Badge variant={PRIORITY_VARIANT[r.priority]} className="mt-0.5 w-14 justify-center capitalize">{r.priority}</Badge>
                  <span className="text-sm">{r.text}</span>
                </Link>
              ))
            )}
          </div>
        </Card>

        {/* Protected endpoints */}
        <Card>
          <CardHeader><CardTitle>Protected endpoints</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-baseline justify-between text-sm">
              <span><span className="num text-xl font-semibold text-ok">{o.endpoints.online}</span> <span className="text-muted">online</span></span>
              <span><span className={cn("num text-xl font-semibold", o.endpoints.offline ? "text-warn" : "text-muted")}>{o.endpoints.offline}</span> <span className="text-muted">offline</span></span>
              <span><span className="num text-xl font-semibold text-muted">{o.endpoints.unmanaged}</span> <span className="text-muted">no agent</span></span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" role="img" aria-label={`${coverage}% of endpoints reporting`}>
              <div className="h-full rounded-full bg-ok" style={{ width: `${coverage}%` }} />
            </div>
            {o.offlineEndpoints.length ? (
              <ul className="space-y-1 text-sm">
                {o.offlineEndpoints.map((e) => (
                  <li key={e.id} className="flex justify-between gap-2">
                    {canAssets ? <Link href={`/assets/${e.id}`} className="truncate hover:text-accent">{e.name}</Link> : <span className="truncate">{e.name}</span>}
                    <span className="text-xs text-muted">last seen {timeAgo(e.lastSeen)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted">All security agents are reporting.</p>
            )}
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-5 xl:grid-cols-2">
        {/* Active incidents */}
        <Card>
          <CardHeader>
            <CardTitle>Active incidents</CardTitle>
            <Link href="/soc/incidents" className="text-xs text-accent hover:underline">All incidents →</Link>
          </CardHeader>
          <div className="divide-y divide-border">
            {o.activeIncidents.length === 0 ? (
              <div className="p-4 text-sm text-muted">No active incidents.</div>
            ) : (
              o.activeIncidents.map((i) => (
                <Link key={i.id} href={`/soc/incidents/${i.id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-2/60">
                  <span className="num w-16 shrink-0 font-mono text-xs text-faint">INC-{i.ref}</span>
                  <SeverityBadge severity={i.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{i.title}</div>
                    <div className="text-xs text-muted">Opened {fmtDateTime(i.createdAt)} · updated {timeAgo(i.updatedAt)}</div>
                  </div>
                  <StatusBadge status={i.status} />
                </Link>
              ))
            )}
          </div>
        </Card>

        {/* Critical vulnerabilities */}
        <Card>
          <CardHeader>
            <CardTitle>Patch these first</CardTitle>
            <Link href="/vulnerabilities" className="text-xs text-accent hover:underline">All priorities →</Link>
          </CardHeader>
          <div className="divide-y divide-border">
            {o.topVulns.length === 0 ? (
              <div className="p-4 text-sm text-muted">No open vulnerabilities.</div>
            ) : (
              o.topVulns.map((v) => (
                <Link key={v.cve} href={`/vulnerabilities?cve=${v.cve}&tenant=${o.tenant.id}`} className="block px-4 py-2.5 hover:bg-surface-2/60">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium">{v.cve}</span>
                    {v.kev ? <Badge variant="danger">Actively exploited</Badge> : null}
                    {v.kevRansomware ? <Badge variant="danger">Used by ransomware</Badge> : null}
                  </div>
                  <div className="mt-0.5 truncate text-xs text-muted">
                    {v.title ?? "Unpatched software"} · {v.affectedAssets} system{v.affectedAssets === 1 ? "" : "s"}
                    {v.internetFacing ? ` (${v.internetFacing} internet-facing)` : ""}
                    {v.epss != null ? ` · ${(v.epss * 100).toFixed(1)}% chance of exploitation in 30 days` : ""}
                    {v.kevDueDate ? ` · fix by ${v.kevDueDate}` : ""}
                  </div>
                </Link>
              ))
            )}
          </div>
        </Card>
      </section>

      <section className="grid gap-5 xl:grid-cols-3">
        {/* Recent detections */}
        <Card>
          <CardHeader><CardTitle>Recent detections</CardTitle></CardHeader>
          <div className="divide-y divide-border">
            {o.recentAlerts.length === 0 ? (
              <div className="p-4 text-sm text-muted">No detections in the last 30 days.</div>
            ) : (
              o.recentAlerts.map((a) => (
                <div key={a.id} className="flex items-center gap-3 px-4 py-2">
                  <SeverityBadge severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm">{a.title}</div>
                    <div className="text-xs text-muted">{fmtDateTime(a.occurredAt)} · {a.status === "RESOLVED" || a.status === "FALSE_POSITIVE" ? "closed by the SOC" : "under review"}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Actions taken by the SOC */}
        <Card>
          <CardHeader><CardTitle>Actions taken by the SOC</CardTitle></CardHeader>
          <div className="divide-y divide-border">
            {o.actions.length === 0 ? (
              <div className="p-4 text-sm text-muted">No containment actions have been needed.</div>
            ) : (
              o.actions.map((a) => {
                const body = (
                  <>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm">{ACTION_LABEL[a.action] ?? a.action.replaceAll("_", " ")}</div>
                      <div className="truncate text-xs text-muted">{[a.assetName, a.identity].filter(Boolean).join(" · ") || "—"} · {timeAgo(a.executedAt ?? a.createdAt)}</div>
                    </div>
                    <StatusBadge status={a.status} />
                  </>
                );
                return a.incidentId ? (
                  <Link key={a.id} href={`/soc/incidents/${a.incidentId}`} className="flex items-center gap-3 px-4 py-2 hover:bg-surface-2/60">{body}</Link>
                ) : (
                  <div key={a.id} className="flex items-center gap-3 px-4 py-2">{body}</div>
                );
              })
            )}
          </div>
        </Card>

        {/* Threats targeting the organisation */}
        <Card>
          <CardHeader><CardTitle>Threats relevant to you</CardTitle></CardHeader>
          <div className="divide-y divide-border">
            {o.threats.length === 0 ? (
              <div className="p-4 text-sm text-muted">No current advisories match your sector or systems.</div>
            ) : (
              o.threats.map((t) => (
                <a key={t.id} href={t.url} target="_blank" rel="noreferrer" className="block px-4 py-2.5 hover:bg-surface-2/60">
                  <div className="flex items-start gap-1.5 text-sm font-medium">
                    <span className="line-clamp-2">{t.title}</span>
                    <ExternalLink className="mt-0.5 size-3 shrink-0 text-faint" aria-hidden />
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
                    <span>{t.source}</span>·<span>{fmtDateTime(t.publishedAt)}</span>
                    {t.affectsEstate ? <Badge variant="danger">Affects your systems</Badge> : null}
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
