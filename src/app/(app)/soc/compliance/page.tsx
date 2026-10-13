import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { requireAccess } from "@/lib/auth/session";
import { ISM_RELEASE } from "@/lib/compliance/ism-catalogue";
import { ismText } from "@/lib/compliance/refs";
import { STRATEGIES, type StrategyId } from "@/lib/essential-eight/requirements";
import { COMPLIANCE_WINDOWS, complianceSignals, type ComplianceWindow, type RefSignal } from "@/lib/services/compliance";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "ISM & Essential Eight" };

const SHORT: Record<StrategyId, string> = {
  patch_applications: "Patch apps",
  patch_os: "Patch OS",
  mfa: "MFA",
  restrict_admin: "Admin privileges",
  application_control: "App control",
  office_macros: "Office macros",
  user_app_hardening: "App hardening",
  regular_backups: "Backups",
};

const queue = (params: Record<string, string>, days: number) => `/soc/alerts?${new URLSearchParams({ ...params, days: String(days) })}`;

/** Where detections touched ISM controls and Essential Eight strategies, beside each customer's assessed maturity. */
export default async function CompliancePage({ searchParams }: { searchParams: Promise<{ days?: string }> }) {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const sp = await searchParams;
  const days = (COMPLIANCE_WINDOWS as readonly number[]).includes(Number(sp.days)) ? (Number(sp.days) as ComplianceWindow) : 30;
  const ws = await currentWorkspace(ctx);
  const data = await complianceSignals(ctx, ws.tenantIds, days);
  const e8 = new Map(data.e8.map((row) => [row.id, row]));
  const scope = ws.tenant ? ws.tenant.name : "all customers";
  const assessed = data.customers.filter((c) => c.assessed).length;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect & respond"
        title="ISM & Essential Eight"
        description={`Detections mapped to ISM controls and Essential Eight strategies across ${scope}, set beside each customer's latest Essential Eight assessment.`}
        actions={
          <nav aria-label="Time window" className="flex gap-1 rounded-md border border-border p-0.5 text-xs">
            {COMPLIANCE_WINDOWS.map((w) => (
              <Link key={w} href={`/soc/compliance?days=${w}`} aria-current={w === days ? "page" : undefined} className={cn("rounded px-2.5 py-1", w === days ? "bg-surface-2 font-medium text-fg" : "text-muted hover:text-fg")}>{w} days</Link>
            ))}
          </nav>
        }
      />

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Mapped detections" value={data.mappedAlerts} detail={`of ${data.alerts.toLocaleString("en-AU")} active-lane alerts`} />
        <Stat label="ISM controls exercised" value={data.ism.length} detail={`ISM ${ISM_RELEASE.version}`} />
        <Stat label="E8 strategies exercised" value={data.e8.length} detail="of 8 strategies" />
        <Stat label="Customers assessed" value={assessed} detail={`of ${data.customers.length} in scope`} />
      </section>

      {!data.mappedAlerts ? (
        <EmptyState title={`No detections in the last ${days} days were mapped to ISM or Essential Eight`}>
          Wedgetail sends ISM and Essential Eight references with every AWS detection. Connect it under <Link href="/integrations/new" className="text-accent hover:underline">Integrations</Link>.
        </EmptyState>
      ) : null}

      <Card>
        <CardHeader className="flex-wrap">
          <CardTitle>Essential Eight by customer</CardTitle>
          <span className="text-xs text-muted">Assessed maturity · mapped detections in the last {days} days</span>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <Table>
            <THead>
              <TR>
                <TH>Customer</TH>
                {STRATEGIES.map((s) => <TH key={s.id} className="text-center" title={s.label}>{SHORT[s.id]}</TH>)}
              </TR>
            </THead>
            <TBody>
              {data.customers.map((c) => (
                <TR key={c.tenantId}>
                  <TD>
                    <div className="font-medium">{c.name}</div>
                    <div className="text-xs text-muted">{c.assessedAt ? `Assessed ${fmtDateTime(c.assessedAt)}` : "Not assessed"}</div>
                  </TD>
                  {STRATEGIES.map((s) => {
                    const level = c.assessed?.[s.id];
                    const hits = c.alerts[s.id] ?? 0;
                    return (
                      <TD key={s.id} className="text-center">
                        <div className={cn("text-sm font-medium", level === undefined ? "text-faint" : level === 0 ? "text-danger" : level === 1 ? "text-warn" : "text-fg")}>{level === undefined ? "—" : `ML${level}`}</div>
                        {hits ? <Link href={queue({ tenant: c.tenantId, e8: s.id }, days)} className="text-xs text-accent hover:underline">{hits} detection{hits === 1 ? "" : "s"}</Link> : <div className="text-xs text-faint">0</div>}
                      </TD>
                    );
                  })}
                </TR>
              ))}
            </TBody>
          </Table>
          {!data.customers.length ? <p className="px-4 py-6 text-sm text-muted">No operational customers in this workspace.</p> : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Essential Eight strategies</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <SignalTable rows={STRATEGIES.map((s) => ({ key: s.id, anchor: `e8-${s.id}`, label: s.label, row: e8.get(s.id), href: queue({ e8: s.id }, days) }))} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-wrap">
          <CardTitle>ISM controls</CardTitle>
          <span className="text-xs text-muted">Most detections first</span>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          {data.ism.length
            ? <SignalTable rows={data.ism.map((row) => ({ key: row.id, anchor: row.id, label: row.id, detail: ismText(row.id) ?? "Not in the bundled ISM snapshot.", mono: true, row, href: queue({ ism: row.id }, days) }))} />
            : <p className="px-4 py-6 text-sm text-muted">No detections mapped to ISM controls in this window.</p>}
        </CardContent>
      </Card>

      <div className="space-y-1 text-xs text-muted">
        <p>A mapped detection is evidence that a control area is being exercised or attacked. It does not rate a control as met. Wedgetail&apos;s own ISM status and Essential Eight evidence assessment need its API and are not connected yet. ATT&amp;CK techniques from the same detections are on <Link href="/detections/attack" className="text-accent hover:underline">ATT&amp;CK coverage</Link>.</p>
        <p>ISM {ISM_RELEASE.version} (published {ISM_RELEASE.published}) control text © Commonwealth of Australia, licensed under CC BY 4.0. Essential Eight maturity model © Commonwealth of Australia.</p>
      </div>
    </div>
  );
}

function Stat({ label, value, detail }: { label: string; value: number; detail: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface px-3 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</div>
      <div className="num mt-1 text-lg font-semibold">{value.toLocaleString("en-AU")}</div>
      <div className="text-xs text-muted">{detail}</div>
    </div>
  );
}

function SignalTable({ rows }: { rows: { key: string; anchor: string; label: string; detail?: string; mono?: boolean; row?: RefSignal; href: string }[] }) {
  return (
    <Table>
      <THead>
        <TR>
          <TH>Control</TH>
          <TH className="text-right">Detections</TH>
          <TH className="text-right">Open</TH>
          <TH className="text-right">High / critical</TH>
          <TH className="text-right">Customers</TH>
          <TH>Last seen</TH>
        </TR>
      </THead>
      <TBody>
        {rows.map(({ key, anchor, label, detail, mono, row, href }) => (
          <TR key={key} id={anchor} className="scroll-mt-20 target:bg-accent-soft">
            <TD className="max-w-xl">
              <div className={cn("font-medium", mono && "font-mono")}>{label}</div>
              {detail ? <div className="mt-0.5 text-xs text-muted">{detail}</div> : null}
            </TD>
            <TD className="num text-right">{row ? <Link href={href} className="text-accent hover:underline">{row.alerts}</Link> : <span className="text-faint">0</span>}</TD>
            <TD className="num text-right">{row?.open ?? 0}</TD>
            <TD className={cn("num text-right", row?.highOrCritical ? "text-sev-high" : undefined)}>{row?.highOrCritical ?? 0}</TD>
            <TD className="num text-right">{row?.customers ?? 0}</TD>
            <TD className="text-xs text-muted">{row ? <span title={fmtDateTime(row.lastSeen)}>{timeAgo(row.lastSeen)}</span> : "—"}</TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}
