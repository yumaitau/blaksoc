import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, PageHeader, RiskScore } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { requireAccess } from "@/lib/auth/session";
import { msspOverview } from "@/lib/services/dashboard";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { EnterWorkspace } from "./enter-workspace";

export const metadata = { title: "Customers" };

/** One row per customer: who needs attention, and a one-click jump into their workspace. */
export default async function MsspPage() {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const rows = await msspOverview(ctx);
  const totals = rows.reduce((t, r) => ({ critical: t.critical + r.criticalAlerts, incidents: t.incidents + r.incidents, offline: t.offline + r.endpointsOffline, kev: t.kev + r.kevExposure }), { critical: 0, incidents: 0, offline: 0, kev: 0 });

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Operate"
        title="Customers"
        description={`${rows.length} customer${rows.length === 1 ? "" : "s"} · ${totals.critical} critical alerts awaiting triage · ${totals.incidents} active incidents · ${totals.offline} agents offline · ${totals.kev} open KEV exposures.`}
      />
      <Card>
        {rows.length === 0 ? (
          <div className="p-4"><EmptyState title="No customers">No customer tenants are in your scope.</EmptyState></div>
        ) : (
          <Table>
            <THead>
              <tr className="border-b border-border">
                <TH>Customer</TH>
                <TH>Risk</TH>
                <TH className="text-right">Alerts</TH>
                <TH className="text-right">Incidents</TH>
                <TH className="text-right">Endpoints</TH>
                <TH>Health</TH>
                <TH className="text-right">KEV exposure</TH>
                <TH>Last alert</TH>
                <TH>Sectors</TH>
                <TH><span className="sr-only">Actions</span></TH>
              </tr>
            </THead>
            <TBody>
              {rows.map((r) => (
                <TR key={r.id}>
                  <TD>
                    <Link href={`/soc/alerts?tenant=${r.id}`} className="font-medium hover:text-accent">{r.name}</Link>
                    <div className="text-[11px] text-faint">{r.slug} · {r.deploymentMode}</div>
                  </TD>
                  <TD><RiskScore score={r.risk} /></TD>
                  <TD className="text-right">
                    <Link href={`/soc/alerts?tenant=${r.id}`} className="num hover:text-accent">{r.alerts}</Link>
                    {r.criticalAlerts ? (
                      <Link href={`/soc/alerts?tenant=${r.id}&minRisk=70&status=NEW`} className="ml-2">
                        <Badge variant="danger">{r.criticalAlerts} critical</Badge>
                      </Link>
                    ) : null}
                  </TD>
                  <TD className="text-right">
                    <Link href={`/soc/incidents?tenant=${r.id}`} className={cn("num hover:text-accent", r.incidents ? "font-semibold text-sev-high" : "text-muted")}>{r.incidents}</Link>
                  </TD>
                  <TD className="text-right">
                    <Link href={`/assets?tenant=${r.id}&kind=endpoint`} className="num hover:text-accent">{r.endpoints}</Link>
                    {r.endpointsOffline ? <Badge variant="warn" className="ml-2">{r.endpointsOffline} offline</Badge> : null}
                  </TD>
                  <TD>{r.healthAlerts ? <Badge variant="warn">degraded</Badge> : <Badge variant="ok">ok</Badge>}</TD>
                  <TD className="text-right">
                    <Link href={`/vulnerabilities?tenant=${r.id}&kev=1`} className={cn("num hover:text-accent", r.kevExposure ? "font-semibold text-sev-critical" : "text-muted")}>{r.kevExposure}</Link>
                  </TD>
                  <TD className="whitespace-nowrap text-xs text-muted" title={fmtDateTime(r.lastAlertAt)}>{timeAgo(r.lastAlertAt)}</TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {r.sectors.map((s) => <Badge key={s} variant="outline">{s.replaceAll("_", " ").toLowerCase()}</Badge>)}
                    </div>
                  </TD>
                  <TD className="text-right"><EnterWorkspace tenantId={r.id} name={r.name} /></TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
