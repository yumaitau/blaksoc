import { AlertTriangle } from "lucide-react";
import Link from "next/link";
import { EmptyState, PageHeader, SeverityBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { eventSummary, type SearchFilters } from "@/lib/providers/data";
import type { Severity } from "@/lib/providers/types";
import { SEVERITIES } from "@/lib/services/alerts";
import { listTenantDataSources, searchTenantEvents, SearchInputError, type FederatedResult, type SourceStatus } from "@/lib/services/search";
import { fmtDateTime } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Event search" };

type SearchParams = Record<string, string | string[] | undefined>;

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim() || undefined;

const RANGES: [string, string, number][] = [
  ["1h", "Last hour", 3_600_000],
  ["24h", "Last 24 hours", 86_400_000],
  ["7d", "Last 7 days", 7 * 86_400_000],
  ["30d", "Last 30 days", 30 * 86_400_000],
  ["90d", "Last 90 days", 90 * 86_400_000],
  ["365d", "Last year", 365 * 86_400_000],
];

const PARAM_KEYS = ["tenant", "q", "range", "from", "to", "severity", "host", "user", "ip", "archive"] as const;

const STATUS_VARIANT: Record<SourceStatus, "ok" | "warn" | "danger" | "outline"> = { ok: "ok", partial: "warn", error: "danger", unsupported: "outline" };

/** datetime-local values are read as UTC. */
function utc(v: string | undefined): Date | null {
  if (!v) return null;
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(v) ? v : `${v}Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

function huntHref(params: Record<string, string>, extra: Record<string, string> = {}) {
  return `/soc/hunt?${new URLSearchParams({ ...params, ...extra, run: "1" })}`;
}

export default async function HuntPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const tenants = ctx.tenants.filter((t) => t.kind === "customer" && can(ctx, "alert:triage", t.id));
  if (!tenants.length) {
    return (
      <>
        <PageHeader eyebrow="Investigate" title="Event search" />
        <EmptyState title="Event search not available">Your role does not include event search for any customer.</EmptyState>
      </>
    );
  }

  const ws = await currentWorkspace(ctx);
  const pick = (id?: string | null) => (id && tenants.some((t) => t.id === id) ? id : undefined);
  const tenantId = pick(first(sp.tenant)) ?? pick(ws.tenant?.id) ?? tenants[0]!.id;
  const tenant = tenants.find((t) => t.id === tenantId)!;

  const params: Record<string, string> = { tenant: tenantId };
  for (const k of PARAM_KEYS) {
    const v = first(sp[k]);
    if (v && k !== "tenant") params[k] = v;
  }
  const range = RANGES.find(([k]) => k === params.range) ?? RANGES[1]!;
  const now = new Date();
  const from = utc(params.from) ?? new Date(now.getTime() - range[2]);
  const to = utc(params.to) ?? now;
  const severity = params.severity?.split(",").filter((s): s is Severity => (SEVERITIES as readonly string[]).includes(s));
  const filters: SearchFilters = {
    ...(severity?.length ? { severity } : {}),
    ...(params.host ? { host: params.host } : {}),
    ...(params.user ? { user: params.user } : {}),
    ...(params.ip ? { ip: params.ip } : {}),
  };
  const cursor = first(sp.cursor);
  const run = first(sp.run) === "1";

  let result: FederatedResult | null = null;
  let inputError: string | null = null;
  if (run) {
    try {
      result = await searchTenantEvents(ctx, { tenantId, from, to, text: params.q, filters, includeArchive: params.archive === "1", pageSize: 100, cursor });
    } catch (err) {
      if (!(err instanceof SearchInputError)) throw err;
      inputError = err.message;
    }
  }
  const sources = result ? null : await listTenantDataSources(ctx, tenantId);
  const troubled = result?.sources.filter((s) => s.status === "partial" || s.status === "error") ?? [];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Investigate"
        title="Event search"
        description={`Searches ${tenant.name}'s telemetry where it lives: Wazuh indexer, firewall syslog and the cold syslog archive. Nothing is copied into blakSOC.`}
      />

      <form action="/soc/hunt" className="grid grid-cols-2 gap-2 rounded-lg border border-border bg-surface p-3 md:grid-cols-4 xl:grid-cols-8">
        <input type="hidden" name="run" value="1" />
        <div className="col-span-2 md:col-span-4 xl:col-span-3">
          <Label htmlFor="h-q">Query</Label>
          <Input id="h-q" name="q" defaultValue={params.q} placeholder='e.g. powershell, rule.level:>10 AND data.srcip:185.220.*' className="font-mono" />
        </div>
        <div>
          <Label htmlFor="h-tenant">Customer</Label>
          <Select id="h-tenant" name="tenant" defaultValue={tenantId}>
            {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="h-range">Time range</Label>
          <Select id="h-range" name="range" defaultValue={range[0]}>
            {RANGES.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="h-from">From (UTC, optional)</Label>
          <Input id="h-from" name="from" type="datetime-local" defaultValue={params.from} />
        </div>
        <div>
          <Label htmlFor="h-to">To (UTC, optional)</Label>
          <Input id="h-to" name="to" type="datetime-local" defaultValue={params.to} />
        </div>
        <div>
          <Label htmlFor="h-severity">Severity</Label>
          <Select id="h-severity" name="severity" defaultValue={params.severity ?? ""}>
            <option value="">Any</option>
            <option value="high,critical">High and above</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s[0]!.toUpperCase() + s.slice(1)}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="h-host">Host</Label>
          <Input id="h-host" name="host" defaultValue={params.host} placeholder="e.g. DC01" />
        </div>
        <div>
          <Label htmlFor="h-user">User</Label>
          <Input id="h-user" name="user" defaultValue={params.user} placeholder="e.g. svc-backup" />
        </div>
        <div>
          <Label htmlFor="h-ip">IP address</Label>
          <Input id="h-ip" name="ip" defaultValue={params.ip} placeholder="e.g. 185.220.101.47" className="font-mono" />
        </div>
        <label className="flex items-end gap-2 pb-2 text-sm">
          <input type="checkbox" name="archive" value="1" defaultChecked={params.archive === "1"} className="size-4" />
          Include cold syslog archive
        </label>
        <div className="col-span-2 flex items-end gap-2 md:col-span-4 xl:col-span-3 xl:justify-end">
          <Button type="submit" size="sm">Search</Button>
          <Button asChild size="sm" variant="ghost"><Link href={`/soc/hunt?tenant=${tenantId}`}>Reset</Link></Button>
        </div>
      </form>

      {inputError ? (
        <div role="alert" className="rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger">{inputError}</div>
      ) : null}

      {sources ? (
        <Card>
          <CardHeader><CardTitle>Sources for {tenant.name}</CardTitle></CardHeader>
          {sources.length === 0 ? (
            <div className="p-4"><EmptyState title="No event sources">This customer has no SIEM, endpoint or syslog integration yet.</EmptyState></div>
          ) : (
            <ul className="divide-y divide-border text-sm">
              {sources.map((s) => (
                <li key={s.integrationId} className="flex flex-wrap items-center gap-2 px-4 py-2">
                  <Badge variant={s.available ? "ok" : "outline"}>{s.available ? "searchable" : "unsupported"}</Badge>
                  <span className="font-medium">{s.name}</span>
                  <span className="text-xs text-muted">{s.provider}{s.shared ? " · shared" : ""}</span>
                  <span className="ml-auto text-xs text-faint">
                    {s.available ? `${s.capabilities.freeText} query · filters ${s.capabilities.filters.join(", ") || "none"} · ${s.capabilities.tiers.join(" + ")}` : s.reason}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      ) : null}

      {result ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Sources</CardTitle>
              <span className="text-xs text-muted">{fmtDateTime(from)} – {fmtDateTime(to)}</span>
            </CardHeader>
            <ul className="divide-y divide-border text-sm">
              {result.sources.map((s) => (
                <li key={s.integrationId} className="flex flex-wrap items-center gap-2 px-4 py-2">
                  <Badge variant={STATUS_VARIANT[s.status]}>{s.status}</Badge>
                  <span className="font-medium">{s.name}</span>
                  <span className="text-xs text-muted">{s.provider}</span>
                  <span className="num text-xs text-muted">{s.count} shown{s.total !== undefined ? ` of ${s.total}` : ""}{s.tookMs ? ` · ${s.tookMs} ms` : ""}</span>
                  {s.message ? <span className="ml-auto text-xs text-faint">{s.message}</span> : null}
                </li>
              ))}
            </ul>
          </Card>

          {troubled.length ? (
            <div role="status" className="flex items-start gap-3 rounded-lg border border-warn/40 bg-warn/10 px-4 py-3 text-sm">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" />
              <div>
                <div className="font-medium text-warn">Results are incomplete</div>
                <div className="text-muted">{troubled.map((s) => `${s.name}: ${s.message ?? s.status}`).join(" · ")}</div>
              </div>
            </div>
          ) : null}

          <Card>
            {result.events.length === 0 ? (
              <div className="p-4"><EmptyState title="No events match">Widen the time range, loosen the filters, or include the archive.</EmptyState></div>
            ) : (
              <Table>
                <THead>
                  <TR className="hover:bg-transparent">
                    <TH>Time</TH>
                    <TH>Source</TH>
                    <TH>Severity</TH>
                    <TH>Event</TH>
                    <TH>Host</TH>
                    <TH>User</TH>
                    <TH>Source → destination</TH>
                  </TR>
                </THead>
                <TBody>
                  {result.events.map((e) => {
                    const s = eventSummary(e.ocsf);
                    return (
                      <TR key={`${e.provenance.integrationId}:${e.id}`} className="align-top">
                        <TD className="whitespace-nowrap text-xs text-muted">{fmtDateTime(new Date(e.time))}</TD>
                        <TD className="whitespace-nowrap">
                          <Badge variant="accent">{e.provenance.provider}</Badge>{" "}
                          {e.provenance.tier === "cold" ? <Badge variant="intel" title={e.provenance.location}>archive</Badge> : null}
                        </TD>
                        <TD><SeverityBadge severity={s.severity === "unknown" ? "informational" : s.severity} /></TD>
                        <TD className="max-w-xl">
                          <details>
                            <summary className="cursor-pointer truncate font-medium">{s.title}</summary>
                            <div className="mt-1 text-[11px] text-faint">{s.className} · {e.provenance.location} · id {e.id}</div>
                            <pre className="mt-1 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-2 p-2 text-[11px]">{typeof e.raw === "string" ? e.raw : JSON.stringify(e.raw, null, 2)}</pre>
                          </details>
                        </TD>
                        <TD className="max-w-40 truncate text-xs">{s.host ?? <span className="text-faint">—</span>}</TD>
                        <TD className="max-w-36 truncate text-xs">{s.user ?? <span className="text-faint">—</span>}</TD>
                        <TD className="whitespace-nowrap font-mono text-[11px]">{s.src || s.dst ? `${s.src ?? "?"} → ${s.dst ?? "?"}` : <span className="text-faint">—</span>}</TD>
                      </TR>
                    );
                  })}
                </TBody>
              </Table>
            )}
            <div className="flex items-center justify-between gap-3 border-t border-border px-4 py-2.5 text-xs text-muted">
              <span className="num">{result.events.length} events on this page</span>
              <div className="flex gap-2">
                {cursor ? <Button asChild size="sm" variant="secondary"><Link href={huntHref(params)}>First page</Link></Button> : null}
                {/* The window is pinned so a relative range does not move under the cursor. */}
                {result.cursor ? <Button asChild size="sm" variant="secondary"><Link href={huntHref(params, { cursor: result.cursor, from: from.toISOString(), to: to.toISOString() })}>Next page</Link></Button> : null}
              </div>
            </div>
          </Card>
        </>
      ) : null}
    </div>
  );
}
