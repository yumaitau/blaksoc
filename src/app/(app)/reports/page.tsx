import Link from "next/link";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { REPORT_KINDS } from "@/lib/reports/generate";
import { listIncidents } from "@/lib/services/incidents";
import { listReports } from "@/lib/services/reports";
import { fmtDateTime } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { GenerateReportForm } from "./generate-form";

export const metadata = { title: "Reports" };

const kindLabel = (k: string) => (REPORT_KINDS as Record<string, { label: string }>)[k]?.label ?? k;
const day = (d: Date) => d.toISOString().slice(0, 10);

export default async function ReportsPage({ searchParams }: { searchParams: Promise<{ kind?: string; tenant?: string; incident?: string }> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  if (!can(ctx, "report:read")) {
    return (
      <>
        <PageHeader eyebrow="Govern" title="Reports" />
        <EmptyState title="No access to reports">Your role does not include report access. Ask an administrator if you need it.</EmptyState>
      </>
    );
  }
  const ws = await currentWorkspace(ctx);
  const genTenants = ctx.tenants.filter((t) => t.kind === "customer" && can(ctx, "report:generate", t.id));
  const [reports, incidents] = await Promise.all([
    listReports(ctx, ws.tenantIds),
    genTenants.length && can(ctx, "incident:read") ? listIncidents(ctx, { tenantIds: genTenants.map((t) => t.id), limit: 200 }).catch(() => []) : Promise.resolve([]),
  ]);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Govern"
        title="Reports"
        description={`Generated reports for ${ws.tenant ? ws.tenant.name : "all customers"}. Every section is labelled as observed evidence or interpretation.`}
      />

      {genTenants.length ? (
        <Card>
          <CardHeader><CardTitle>Generate a report</CardTitle></CardHeader>
          <CardContent>
            <GenerateReportForm
              kinds={Object.entries(REPORT_KINDS).map(([value, k]) => ({ value, label: k.label }))}
              tenants={genTenants.map((t) => ({ value: t.id, label: t.name }))}
              incidents={incidents.map((i) => ({ id: i.id, tenantId: i.tenantId, label: `INC-${i.ref} · ${i.title}` }))}
              initial={{ kind: sp.kind, tenant: sp.tenant, incident: sp.incident }}
            />
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Generated reports</CardTitle>
          <span className="text-xs text-muted">{reports.length} shown</span>
        </CardHeader>
        {reports.length === 0 ? (
          <div className="p-4"><EmptyState title="No reports yet">{genTenants.length ? "Generate one above." : "Reports your SOC shares with you will appear here."}</EmptyState></div>
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>Title</TH>
                <TH>Customer</TH>
                <TH>Type</TH>
                <TH>Period</TH>
                <TH>Generated</TH>
              </TR>
            </THead>
            <TBody>
              {reports.map((r) => (
                <TR key={r.id}>
                  <TD><Link href={`/reports/${r.id}`} className="font-medium hover:text-accent hover:underline">{r.title}</Link></TD>
                  <TD className="text-muted">{r.tenantName}</TD>
                  <TD><Badge variant="outline">{kindLabel(r.kind)}</Badge></TD>
                  <TD className="num whitespace-nowrap text-xs text-muted">{day(r.periodStart)} → {day(r.periodEnd)}</TD>
                  <TD className="whitespace-nowrap text-xs text-muted">{fmtDateTime(r.createdAt)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
