import Link from "next/link";
import { AttackChips, EmptyState, IntelVerdict, PageHeader, RiskScore, SeverityBadge, StatusBadge } from "@/components/soc/indicators";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { ALERT_STATUSES, listAlerts, listSavedViews, SEVERITIES, type AlertFilters } from "@/lib/services/alerts";
import { listIncidents } from "@/lib/services/incidents";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { BulkBar, QueueSelection, RowCheckbox, SelectAllCheckbox } from "./queue-selection";
import { SaveView } from "./save-view";

export const metadata = { title: "Alert queue" };

const FILTER_KEYS = ["tenant", "status", "severity", "assignee", "intel", "intelLabel", "q", "technique", "category", "minRisk", "sort"] as const;
const PAGE_SIZE = 50;

type SearchParams = Record<string, string | string[] | undefined>;

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim() || undefined;
const csv = <T extends string>(v: string | undefined, allowed: readonly T[]) => v?.split(",").filter((x): x is T => (allowed as readonly string[]).includes(x));

function queueHref(filters: Record<string, string>, extra: Record<string, string | number> = {}) {
  const qs = new URLSearchParams({ ...filters, ...Object.fromEntries(Object.entries(extra).map(([k, v]) => [k, String(v)])) }).toString();
  return qs ? `/soc/alerts?${qs}` : "/soc/alerts";
}

const flatten = (f: Record<string, string | string[]>) => Object.fromEntries(Object.entries(f).map(([k, v]) => [k, Array.isArray(v) ? v.join(",") : v]));

/** "via Wazuh (prod) · rule 5710": which integration collected the alert and the source rule that fired. */
const viaLine = (a: { integrationName: string | null; ruleId: string | null }) =>
  [a.integrationName && `via ${a.integrationName}`, a.ruleId && `rule ${a.ruleId}`].filter(Boolean).join(" · ");

const sameFilters = (a: Record<string, string>, b: Record<string, string>) =>
  Object.keys(a).length === Object.keys(b).length && Object.entries(a).every(([k, v]) => b[k] === v);

export default async function AlertQueue({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const ws = await currentWorkspace(ctx);

  const filters: Record<string, string> = {};
  for (const k of FILTER_KEYS) {
    const v = first(sp[k]);
    if (v) filters[k] = v;
  }
  const offset = Math.max(0, Number(first(sp.offset)) || 0);
  const minRisk = filters.minRisk ? Number(filters.minRisk) : undefined;

  const query: AlertFilters = {
    tenantIds: filters.tenant ? [filters.tenant] : ws.tenantIds,
    status: csv(filters.status, ALERT_STATUSES),
    severity: csv(filters.severity, SEVERITIES),
    assignee: filters.assignee,
    intel: filters.intel === "match" ? "match" : undefined,
    intelLabel: filters.intelLabel,
    q: filters.q,
    technique: filters.technique,
    category: filters.category,
    minRisk: Number.isFinite(minRisk) ? minRisk : undefined,
    sort: filters.sort === "newest" || filters.sort === "oldest" ? filters.sort : "risk",
    limit: PAGE_SIZE,
    offset,
  };

  const canTriage = can(ctx, "alert:triage");
  const [{ rows, total }, views, openIncidents] = await Promise.all([
    listAlerts(ctx, query),
    listSavedViews(ctx, "/soc/alerts"),
    canTriage && can(ctx, "incident:read") ? listIncidents(ctx, { tenantIds: ws.tenantIds, open: true }) : Promise.resolve([]),
  ]);

  const customers = ctx.tenants.filter((t) => t.kind === "customer");
  const scope = filters.tenant ? (customers.find((c) => c.id === filters.tenant)?.name ?? "selected customer") : ws.tenant ? ws.tenant.name : "all customers";

  return (
    <div className="space-y-4">
      <PageHeader eyebrow="Operate" title="Alert queue" description={`Triage queue for ${scope}. Sorted by blakSOC risk unless you choose otherwise.`} />

      {/* Saved views */}
      <nav aria-label="Saved views" className="flex flex-wrap items-center gap-1.5">
        <Link href="/soc/alerts" className={cn("rounded-full border px-2.5 py-1 text-xs", Object.keys(filters).length === 0 ? "border-accent bg-accent-soft text-accent" : "border-border text-muted hover:text-fg")}>
          All alerts
        </Link>
        {views.map((view) => ({ ...view, filters: flatten(view.filters) })).map((v) => (
          <Link
            key={v.id}
            href={queueHref(v.filters)}
            className={cn("rounded-full border px-2.5 py-1 text-xs", sameFilters(v.filters, filters) ? "border-accent bg-accent-soft text-accent" : "border-border text-muted hover:text-fg", !v.builtin && "border-dashed")}
          >
            {v.name}
          </Link>
        ))}
        <SaveView filters={filters} />
      </nav>

      <FilterBar filters={filters} customers={customers} />

      <Card>
        <QueueSelection rows={rows.map((r) => ({ id: r.id, tenantId: r.tenantId }))}>
          <BulkBar statuses={ALERT_STATUSES} openIncidents={openIncidents.map((i) => ({ id: i.id, ref: i.ref, title: i.title, tenantId: i.tenantId, tenantName: i.tenantName }))} canTriage={canTriage} />
          {rows.length === 0 ? (
            <div className="p-4">
              <EmptyState title="No alerts match">Try widening the filters or choosing another view.</EmptyState>
            </div>
          ) : (
            <Table>
              <THead>
                <TR className="hover:bg-transparent">
                  {canTriage ? <TH className="w-8"><SelectAllCheckbox /></TH> : null}
                  <TH>Severity</TH>
                  <TH>Risk</TH>
                  <TH>Customer</TH>
                  <TH>Alert</TH>
                  <TH>Asset</TH>
                  <TH>User</TH>
                  <TH>Source</TH>
                  <TH>Threat intel</TH>
                  <TH>ATT&CK</TH>
                  <TH>Occurred</TH>
                  <TH>Status</TH>
                  <TH>Assignee</TH>
                </TR>
              </THead>
              <TBody>
                {rows.map((a) => (
                  <TR key={a.id}>
                    {canTriage ? <TD><RowCheckbox id={a.id} tenantId={a.tenantId} title={a.title} /></TD> : null}
                    <TD><SeverityBadge severity={a.severity} /></TD>
                    <TD><RiskScore score={a.riskScore} factors={a.riskFactors} /></TD>
                    <TD className="max-w-36 truncate text-xs text-muted">{a.tenantName}</TD>
                    <TD className="max-w-md">
                      <Link href={`/soc/alerts/${a.id}`} className="block truncate font-medium hover:text-accent">{a.title}</Link>
                      <div className="truncate text-[11px] text-faint">
                        {a.category ?? "uncategorised"}
                        {a.incidentId ? <> · <Link href={`/soc/incidents/${a.incidentId}`} className="text-accent hover:underline">on incident</Link></> : null}
                      </div>
                    </TD>
                    <TD className="max-w-40 truncate text-xs">
                      {a.assetId ? <Link href={`/assets/${a.assetId}`} className="hover:text-accent">{a.assetName}</Link> : <span className="text-faint">—</span>}
                    </TD>
                    <TD className="max-w-36 truncate text-xs">{a.userName ?? <span className="text-faint">—</span>}</TD>
                    <TD className="max-w-40 text-xs text-muted">
                      <div className="truncate">{a.source}</div>
                      {viaLine(a) ? <div className="truncate text-[11px] text-faint" title={viaLine(a)}>{viaLine(a)}</div> : null}
                    </TD>
                    <TD><IntelVerdict verdict={a.intelVerdict} /></TD>
                    <TD><AttackChips techniques={a.attackTechniques} max={2} /></TD>
                    <TD className="whitespace-nowrap text-xs text-muted" title={fmtDateTime(a.occurredAt)}>{timeAgo(a.occurredAt)}</TD>
                    <TD><StatusBadge status={a.status} /></TD>
                    <TD className="max-w-32 truncate text-xs">{a.assigneeName ?? <span className="text-faint">Unassigned</span>}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </QueueSelection>
        <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-2.5 text-xs text-muted">
          <span className="num">
            {rows.length === 0 ? `No alerts on this page · ${total} total` : `${offset + 1}–${offset + rows.length} of ${total}`}
          </span>
          <div className="flex gap-2">
            {offset > 0 ? <Button asChild size="sm" variant="secondary"><Link href={queueHref(filters, { offset: Math.max(0, offset - PAGE_SIZE) })}>Previous</Link></Button> : null}
            {offset + rows.length < total ? <Button asChild size="sm" variant="secondary"><Link href={queueHref(filters, { offset: offset + PAGE_SIZE })}>Next</Link></Button> : null}
          </div>
        </div>
      </Card>
    </div>
  );
}

const OPEN = "NEW,TRIAGING,INVESTIGATING,ESCALATED";

/** Plain GET form: filters live in the URL so every queue state is linkable and saveable. */
function FilterBar({ filters, customers }: { filters: Record<string, string>; customers: { id: string; name: string }[] }) {
  const statusOptions: [string, string][] = [["", "Any status"], [OPEN, "Open (not contained or closed)"], ...ALERT_STATUSES.map((s): [string, string] => [s, s.replaceAll("_", " ")])];
  const severityOptions: [string, string][] = [["", "Any severity"], ["critical", "Critical"], ["high,critical", "High and above"], ...SEVERITIES.map((s): [string, string] => [s, s[0]!.toUpperCase() + s.slice(1)])];
  const withCurrent = (opts: [string, string][], v?: string) => (v && !opts.some(([k]) => k === v) ? [...opts, [v, v] as [string, string]] : opts);

  return (
    <form action="/soc/alerts" className="grid grid-cols-2 gap-2 rounded-lg border border-border bg-surface p-3 md:grid-cols-4 xl:grid-cols-9">
      <div className="col-span-2">
        <Label htmlFor="f-q">Search</Label>
        <Input id="f-q" name="q" defaultValue={filters.q} placeholder="Title, user or asset" />
      </div>
      <div>
        <Label htmlFor="f-tenant">Customer</Label>
        <Select id="f-tenant" name="tenant" defaultValue={filters.tenant ?? ""}>
          <option value="">Workspace</option>
          {customers.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor="f-status">Status</Label>
        <Select id="f-status" name="status" defaultValue={filters.status ?? ""}>
          {withCurrent(statusOptions, filters.status).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor="f-severity">Severity</Label>
        <Select id="f-severity" name="severity" defaultValue={filters.severity ?? ""}>
          {withCurrent(severityOptions, filters.severity).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor="f-assignee">Assignee</Label>
        <Select id="f-assignee" name="assignee" defaultValue={filters.assignee ?? ""}>
          {withCurrent([["", "Anyone"], ["me", "Me"], ["unassigned", "Unassigned"]], filters.assignee).map(([v, l]) => <option key={v} value={v}>{v && !["me", "unassigned"].includes(v) ? "Selected analyst" : l}</option>)}
        </Select>
      </div>
      <div>
        <Label htmlFor="f-intel">Threat intel</Label>
        <Select id="f-intel" name="intel" defaultValue={filters.intel ?? ""}>
          <option value="">Any</option>
          <option value="match">Malicious or suspicious</option>
        </Select>
      </div>
      <div>
        <Label htmlFor="f-risk">Min risk</Label>
        <Input id="f-risk" name="minRisk" type="number" min={0} max={100} defaultValue={filters.minRisk} placeholder="0–100" />
      </div>
      <div>
        <Label htmlFor="f-sort">Sort</Label>
        <Select id="f-sort" name="sort" defaultValue={filters.sort ?? "risk"}>
          <option value="risk">Highest risk</option>
          <option value="newest">Newest</option>
          <option value="oldest">Oldest</option>
        </Select>
      </div>
      <div>
        <Label htmlFor="f-technique">ATT&CK technique</Label>
        <Input id="f-technique" name="technique" defaultValue={filters.technique} placeholder="T1486" className="font-mono" />
      </div>
      <div>
        <Label htmlFor="f-category">Category</Label>
        <Input id="f-category" name="category" defaultValue={filters.category} placeholder="e.g. windows" />
      </div>
      <div>
        <Label htmlFor="f-label">Intel label</Label>
        <Input id="f-label" name="intelLabel" defaultValue={filters.intelLabel} placeholder="e.g. australia" />
      </div>
      <div className="col-span-2 flex items-end gap-2 md:col-span-4 xl:col-span-6 xl:justify-end">
        <Button type="submit" size="sm">Apply filters</Button>
        <Button asChild size="sm" variant="ghost"><Link href="/soc/alerts">Reset</Link></Button>
      </div>
    </form>
  );
}
