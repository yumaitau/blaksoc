import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { requireAccess } from "@/lib/auth/session";
import { ISM_RELEASE } from "@/lib/compliance/ism-catalogue";
import { ismText } from "@/lib/compliance/refs";
import { STRATEGIES, type StrategyId } from "@/lib/essential-eight/requirements";
import { COMPLIANCE_WINDOWS, complianceSignals, type ComplianceWindow, type RefSignal, type WedgetailControl } from "@/lib/services/compliance";
import type { IsmStatus } from "@/lib/wedgetail/posture";
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
  const connected = data.customers.filter((c) => c.wedgetail).length;
  const wedgetail = new Map(data.wedgetailControls.map((c) => [c.id, c]));
  const ismSignals = new Map(data.ism.map((row) => [row.id, row]));
  // Every control Wedgetail rates or a detection mentions. Gaps first, then the busiest.
  const ismRows = [...new Set([...data.ism.map((r) => r.id), ...wedgetail.keys()])].sort((a, b) =>
    (wedgetail.get(b)?.statuses.not_met ?? 0) - (wedgetail.get(a)?.statuses.not_met ?? 0)
    || (wedgetail.get(b)?.statuses.partial ?? 0) - (wedgetail.get(a)?.statuses.partial ?? 0)
    || (ismSignals.get(b)?.alerts ?? 0) - (ismSignals.get(a)?.alerts ?? 0)
    || a.localeCompare(b));
  const gaps = data.wedgetailControls.filter((c) => c.statuses.not_met > 0).length;
  const single = data.customers.length === 1;

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

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Mapped detections" value={data.mappedAlerts} detail={`of ${data.alerts.toLocaleString("en-AU")} active-lane alerts`} />
        <Stat label="ISM controls exercised" value={data.ism.length} detail={`ISM ${ISM_RELEASE.version}`} />
        <Stat label="E8 strategies exercised" value={data.e8.length} detail="of 8 strategies" />
        <Stat label="Customers assessed" value={assessed} detail={`of ${data.customers.length} in scope`} />
        <Stat label="ISM gaps (Wedgetail)" value={gaps} detail={connected ? `controls rated gap · ${connected} customer${connected === 1 ? "" : "s"} connected` : "No install pulling posture yet"} />
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
                <TH title="ISM control status from the customer's Wedgetail install">Wedgetail ISM</TH>
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
                  <TD className="whitespace-nowrap text-xs">
                    {c.wedgetail ? (
                      <>
                        <div><span className="text-ok">{c.wedgetail.counts.met} met</span> · <span className="text-warn">{c.wedgetail.counts.partial} partly</span> · <span className={c.wedgetail.counts.not_met ? "text-danger" : "text-muted"}>{c.wedgetail.counts.not_met} gap</span></div>
                        <div className={c.wedgetail.error ? "text-danger" : "text-muted"} title={c.wedgetail.error ?? undefined}>{c.wedgetail.error ? "Pull failing" : c.wedgetail.fetchedAt ? `As of ${timeAgo(c.wedgetail.fetchedAt)}` : "Not pulled yet"}</div>
                      </>
                    ) : <span className="text-faint">Not connected</span>}
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
          <p className="border-t border-border px-4 py-2 text-xs text-muted">Wedgetail&apos;s own Essential Eight evidence assessment is not available over its MCP endpoint yet, so maturity here is the customer&apos;s blakSOC assessment.</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-wrap">
          <CardTitle>ISM controls</CardTitle>
          <span className="text-xs text-muted">{connected ? "Wedgetail gaps first, then most detections" : "Most detections first"}</span>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          {ismRows.length
            ? <SignalTable status={connected > 0} rows={ismRows.map((id) => ({ key: id, anchor: id, label: id, detail: ismText(id) ?? wedgetail.get(id)?.title ?? "Not in the bundled ISM snapshot.", mono: true, row: ismSignals.get(id), href: queue({ ism: id }, days), status: wedgetail.get(id) ? <WedgetailStatus control={wedgetail.get(id)!} single={single} /> : undefined }))} />
            : <p className="px-4 py-6 text-sm text-muted">No detections mapped to ISM controls in this window, and no Wedgetail install is pulling ISM status.</p>}
        </CardContent>
      </Card>

      <div className="space-y-1 text-xs text-muted">
        <p>A mapped detection is evidence that a control area is being exercised or attacked. It does not rate a control as met. ISM status comes from each customer&apos;s Wedgetail install (its own control rules, pulled hourly over MCP) where one is connected. ATT&amp;CK techniques from the same detections are on <Link href="/detections/attack" className="text-accent hover:underline">ATT&amp;CK coverage</Link>.</p>
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

const STATUS_LABEL: Record<IsmStatus, string> = { not_met: "Gap", partial: "Partly met", met: "Met", not_applicable: "Outside Wedgetail" };
const STATUS_TONE: Record<IsmStatus, string> = { not_met: "text-danger", partial: "text-warn", met: "text-ok", not_applicable: "text-muted" };

function WedgetailStatus({ control, single }: { control: WedgetailControl; single: boolean }) {
  if (single && control.reasons.length === 1) {
    const only = control.reasons[0]!;
    return <div><div className={cn("font-medium", STATUS_TONE[only.status])}>{STATUS_LABEL[only.status]}</div><div className="mt-0.5 max-w-xs text-xs text-muted">{only.reason}</div></div>;
  }
  const order: IsmStatus[] = ["not_met", "partial", "met", "not_applicable"];
  return <div className="text-xs">{order.filter((s) => control.statuses[s]).map((s) => <div key={s} className={STATUS_TONE[s]}>{STATUS_LABEL[s]} · {control.statuses[s]}</div>)}</div>;
}

function SignalTable({ rows, status = false }: { rows: { key: string; anchor: string; label: string; detail?: string; mono?: boolean; row?: RefSignal; href: string; status?: React.ReactNode }[]; status?: boolean }) {
  return (
    <Table>
      <THead>
        <TR>
          <TH>Control</TH>
          {status ? <TH>Wedgetail status</TH> : null}
          <TH className="text-right">Detections</TH>
          <TH className="text-right">Open</TH>
          <TH className="text-right">High / critical</TH>
          <TH className="text-right">Customers</TH>
          <TH>Last seen</TH>
        </TR>
      </THead>
      <TBody>
        {rows.map(({ key, anchor, label, detail, mono, row, href, status: rating }) => (
          <TR key={key} id={anchor} className="scroll-mt-20 target:bg-accent-soft">
            <TD className="max-w-xl">
              <div className={cn("font-medium", mono && "font-mono")}>{label}</div>
              {detail ? <div className="mt-0.5 text-xs text-muted">{detail}</div> : null}
            </TD>
            {status ? <TD>{rating ?? <span className="text-xs text-faint">Not rated</span>}</TD> : null}
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
