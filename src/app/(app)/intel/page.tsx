import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, IntelVerdict, PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { SECTOR_TAGS, type SectorTag } from "@/db/schema";
import { can, type AccessContext } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { splitTechniqueCoverage } from "@/lib/detections/advisory-coverage";
import { intelMatchesFor } from "@/lib/services/alerts";
import { coveredAttackTechniques, listAdvisories, listFeeds, searchIntel, sightingQueue } from "@/lib/services/intel";
import { cn, fmtDateTime } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { logger } from "@/lib/obs/log";
import { EntitlementToggles, FeedToggle, ShareSightingButton, TagRelevance } from "./intel-controls";

export const metadata = { title: "Threat intelligence" };

const TABS = [
  { key: "australia", label: "Australian threats" },
  { key: "search", label: "Search OpenCTI" },
  { key: "matches", label: "Matches in our customers" },
  { key: "sightings", label: "Sightings feedback" },
  { key: "feeds", label: "Feeds" },
] as const;
type TabKey = (typeof TABS)[number]["key"];

const tagLabel = (t: string) => t.replaceAll("_", " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());

export default async function IntelPage({ searchParams }: { searchParams: Promise<{ tab?: string; q?: string; tag?: string }> }) {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const sp = await searchParams;
  const tab: TabKey = TABS.some((t) => t.key === sp.tab) ? (sp.tab as TabKey) : sp.q ? "search" : "australia";
  const coveredIds = tab === "australia" && can(ctx, "detection:read") ? await coveredAttackTechniques(ctx) : null;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Intelligence"
        title="Threat intelligence"
        description="OpenCTI is the system of record for cyber threat intelligence. blakSOC holds only sector tags, advisories and match state needed to act on it."
      />
      <nav aria-label="Threat intelligence sections" className="flex flex-wrap items-center gap-1 border-b border-border">
        {TABS.map((t) => (
          <Link
            key={t.key}
            href={`/intel?tab=${t.key}`}
            aria-current={tab === t.key ? "page" : undefined}
            className={cn("-mb-px border-b-2 px-3 py-2 text-sm", tab === t.key ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg")}
          >
            {t.label}
          </Link>
        ))}
      </nav>
      {tab === "australia" ? <Australian ctx={ctx} tag={sp.tag} coveredIds={coveredIds} /> : null}
      {tab === "search" ? <Search ctx={ctx} q={sp.q?.trim() ?? ""} /> : null}
      {tab === "matches" ? <Matches ctx={ctx} /> : null}
      {tab === "sightings" ? <Sightings ctx={ctx} /> : null}
      {tab === "feeds" ? <Feeds ctx={ctx} /> : null}
    </div>
  );
}

function TechniqueLine({ named, coveredIds }: { named: string[]; coveredIds: string[] }) {
  const split = splitTechniqueCoverage(named, coveredIds);
  if (!split.covered.length && !split.uncovered.length) return null;
  return (
    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
      {split.covered.map((id) => (
        <Link key={id} href={`/detections/attack?t=${id}`}><Badge variant="ok">{id} covered</Badge></Link>
      ))}
      {split.uncovered.map((id) => (
        <Link key={id} href={`/detections/attack?t=${id}`}><Badge variant="danger">{id} gap</Badge></Link>
      ))}
    </div>
  );
}

function AdvisoryCoverage({ rows, coveredIds }: { rows: { id: string; title: string; attackTechniques: string[] }[]; coveredIds: string[] }) {
  const unique = [...new Set(rows.flatMap((row) => row.attackTechniques))];
  const covered = splitTechniqueCoverage(unique, coveredIds).covered;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Advisory detection coverage</CardTitle>
        <span className="text-xs text-muted">Techniques named in ingested advisories</span>
      </CardHeader>
      <CardContent>
        {unique.length === 0 ? (
          <p className="text-sm text-muted">No ingested advisory names a technique yet.</p>
        ) : (
          <p className="text-sm text-muted">{covered.length} of {unique.length} techniques named in these advisories have an enabled detection.</p>
        )}
      </CardContent>
    </Card>
  );
}

async function Australian({ ctx, tag, coveredIds }: { ctx: AccessContext; tag?: string; coveredIds: string[] | null }) {
  const active = SECTOR_TAGS.includes(tag as SectorTag) ? (tag as SectorTag) : null;
  const all = await listAdvisories(ctx, { limit: 200 });
  const rows = active ? all.filter((a) => a.tags.includes(active)) : all;
  return (
    <div className="space-y-5">
      {coveredIds ? <AdvisoryCoverage rows={rows} coveredIds={coveredIds} /> : null}
      <Card>
      <CardHeader>
        <CardTitle>Australian threat advisories</CardTitle>
        <span className="text-xs text-muted">ACSC and CISA, newest first</span>
      </CardHeader>
      <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-4 py-2.5" role="group" aria-label="Filter by sector tag">
        <Link href="/intel?tab=australia" className={cn("rounded-full border px-2.5 py-0.5 text-xs", !active ? "border-accent bg-accent-soft text-accent" : "border-border text-muted hover:text-fg")} aria-current={!active ? "true" : undefined}>
          All
        </Link>
        {SECTOR_TAGS.map((t) => (
          <Link key={t} href={`/intel?tab=australia&tag=${t}`} aria-current={active === t ? "true" : undefined} className={cn("rounded-full border px-2.5 py-0.5 text-xs", active === t ? "border-accent bg-accent-soft text-accent" : "border-border text-muted hover:text-fg")}>
            {tagLabel(t)}
          </Link>
        ))}
      </div>
      {rows.length === 0 ? (
        <div className="p-4">
          <EmptyState title={active ? `No advisories tagged ${tagLabel(active)}` : "No advisories ingested yet"}>
            The worker ingests ACSC and CISA advisories hourly and normalises them into OpenCTI reports. Check back after the next run.
          </EmptyState>
        </div>
      ) : (
        <div className="divide-y divide-border">
          {rows.map((a) => (
            <div key={a.id} className="px-4 py-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <a href={a.url} target="_blank" rel="noreferrer" className="min-w-0 flex-1 text-sm font-medium hover:text-accent hover:underline">
                  {a.title}
                  <span className="sr-only"> (opens external advisory)</span>
                </a>
                <span className="shrink-0 text-xs text-muted">{a.source} · {fmtDateTime(a.publishedAt)}</span>
              </div>
              {a.summary ? <p className="mt-1 line-clamp-2 text-xs text-muted">{a.summary}</p> : null}
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                {a.tags.map((t) => (
                  <Link key={t} href={`/intel?tab=australia&tag=${t}`}><Badge variant="accent">{tagLabel(t)}</Badge></Link>
                ))}
                {a.cves.map((c) => (
                  <Link key={c} href={`/vulnerabilities?cve=${c}`}><Badge variant="danger" className="font-mono">{c}</Badge></Link>
                ))}
                {a.openctiReportId ? (
                  <Link href={`/intel?tab=search&q=${encodeURIComponent(a.title)}`} className="font-mono text-[11px] text-intel hover:underline" title="Normalised as an OpenCTI report">
                    OpenCTI {a.openctiReportId.length > 20 ? `${a.openctiReportId.slice(0, 20)}…` : a.openctiReportId}
                  </Link>
                ) : (
                  <span className="text-[11px] text-faint">Not yet normalised in OpenCTI</span>
                )}
              </div>
              {coveredIds ? <TechniqueLine named={a.attackTechniques} coveredIds={coveredIds} /> : null}
            </div>
          ))}
        </div>
      )}
      </Card>
    </div>
  );
}

async function Search({ ctx, q }: { ctx: AccessContext; q: string }) {
  const canTag = can(ctx, "intel:write");
  let res: Awaited<ReturnType<typeof searchIntel>> | null = null;
  let failure: string | null = null;
  if (q) {
    try {
      res = await searchIntel(ctx, q);
    } catch (err) {
      logger.error("intel search failed", { err });
      failure = "OpenCTI did not respond. Check the integration health, then try again.";
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>Search OpenCTI</CardTitle>
        <span className="text-xs text-muted">Live query; results are not stored in blakSOC</span>
      </CardHeader>
      <CardContent className="space-y-4">
        <form action="/intel" className="flex gap-2" role="search">
          <input type="hidden" name="tab" value="search" />
          <label htmlFor="intel-q" className="sr-only">Search term</label>
          <Input id="intel-q" name="q" defaultValue={q} placeholder="Indicator, malware, intrusion set, CVE…" className="max-w-xl" />
          <Button type="submit">Search</Button>
        </form>
        {!q ? (
          <p className="text-sm text-muted">Search indicators, malware, actors and reports. Tag results with Australian sector relevance so they surface in customer scoring and dashboards.</p>
        ) : failure ? (
          <p role="alert" className="text-sm text-danger">{failure}</p>
        ) : res && !res.configured ? (
          <EmptyState title="OpenCTI not configured">An administrator needs to connect OpenCTI under Integrations before threat intelligence can be searched.</EmptyState>
        ) : res && res.results.length === 0 ? (
          <EmptyState title="No results">Nothing in OpenCTI matches “{q}”.</EmptyState>
        ) : res ? (
          <Table>
            <THead>
              <TR>
                <TH>Type</TH>
                <TH>Name</TH>
                <TH>Labels</TH>
                <TH>Markings</TH>
                <TH className="text-right">Score</TH>
                <TH>Source</TH>
                <TH>Modified</TH>
                <TH><span className="sr-only">Actions</span></TH>
              </TR>
            </THead>
            <TBody>
              {res.results.map((r) => (
                <TR key={r.id}>
                  <TD className="text-xs text-muted whitespace-nowrap">{r.entityType}</TD>
                  <TD className="max-w-md">
                    <div className="truncate font-mono text-xs" title={r.name}>{r.name}</div>
                    {r.description ? <div className="line-clamp-2 text-xs text-muted">{r.description}</div> : null}
                    <div className="mt-0.5 font-mono text-[10.5px] text-faint">{r.id}</div>
                  </TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {r.sectorTags.map((t) => <Badge key={`s-${t}`} variant="accent">{tagLabel(t)}</Badge>)}
                      {r.labels.map((l) => <Badge key={l} variant="outline">{l}</Badge>)}
                    </div>
                  </TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {r.markings.map((m) => <Badge key={m} variant={/RED/.test(m) ? "danger" : /AMBER/.test(m) ? "warn" : /GREEN/.test(m) ? "ok" : "default"}>{m}</Badge>)}
                    </div>
                  </TD>
                  <TD className="num text-right text-sm">{r.score ?? "—"}</TD>
                  <TD className="text-xs text-muted">{r.createdBy ?? "—"}</TD>
                  <TD className="text-xs text-muted whitespace-nowrap">{fmtDateTime(r.modified)}</TD>
                  <TD className="text-right">
                    {canTag ? <TagRelevance entity={{ id: r.id, entityType: r.entityType, name: r.name }} current={r.sectorTags} allTags={SECTOR_TAGS} /> : null}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        ) : null}
      </CardContent>
    </Card>
  );
}

async function Matches({ ctx }: { ctx: AccessContext }) {
  const ws = await currentWorkspace(ctx);
  const rows = await intelMatchesFor(ctx, { sinceHours: 168, limit: 200, tenantIds: ws.tenantIds });
  return (
    <Card>
      <CardHeader>
        <CardTitle>Matches in our customers (7 days)</CardTitle>
        <span className="text-xs text-muted">{ws.tenant ? ws.tenant.name : "All customers"}</span>
      </CardHeader>
      {rows.length === 0 ? (
        <div className="p-4"><EmptyState title="No intel matches in 7 days">Observables in customer telemetry have not matched OpenCTI indicators this week.</EmptyState></div>
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Indicator</TH>
              <TH>Verdict</TH>
              <TH>Customer</TH>
              <TH>Associations</TH>
              <TH>Matched</TH>
              <TH><span className="sr-only">Alert</span></TH>
            </TR>
          </THead>
          <TBody>
            {rows.map((m) => {
              const assoc = [...m.summary.threatActors, ...m.summary.intrusionSets, ...m.summary.malware, ...m.summary.campaigns];
              return (
                <TR key={m.id}>
                  <TD className="max-w-xs">
                    <div className="truncate font-mono text-xs" title={m.summary.observable.value}>{m.summary.observable.value}</div>
                    <div className="text-[11px] text-muted">{m.summary.observable.type}{m.summary.source ? ` · ${m.summary.source}` : ""}</div>
                  </TD>
                  <TD><IntelVerdict verdict={m.verdict} />{m.score != null ? <span className="num ml-1.5 text-xs text-faint">{m.score}</span> : null}</TD>
                  <TD className="text-sm">{m.tenantName}</TD>
                  <TD>
                    {assoc.length ? (
                      <div className="flex flex-wrap gap-1">
                        {assoc.slice(0, 4).map((a) => <Link key={a} href={`/intel?tab=search&q=${encodeURIComponent(a)}`}><Badge variant="intel">{a}</Badge></Link>)}
                        {assoc.length > 4 ? <span className="text-[11px] text-faint">+{assoc.length - 4}</span> : null}
                      </div>
                    ) : <span className="text-xs text-faint">—</span>}
                  </TD>
                  <TD className="text-xs text-muted whitespace-nowrap">{fmtDateTime(m.matchedAt)}</TD>
                  <TD className="text-right">
                    {m.alertId ? <Link href={`/soc/alerts/${m.alertId}`} className="text-xs text-accent hover:underline">Open alert →</Link> : <span className="text-xs text-faint">No alert</span>}
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Card>
  );
}

const SIGHTING_STATUS: Record<string, { label: string; variant: "default" | "warn" | "ok" | "danger" }> = {
  not_shared: { label: "Not shared", variant: "default" },
  queued: { label: "Queued", variant: "warn" },
  shared: { label: "Shared", variant: "ok" },
  blocked_by_policy: { label: "Blocked by policy", variant: "danger" },
};

async function Sightings({ ctx }: { ctx: AccessContext }) {
  const privacy = (
    <p className="text-xs text-muted">
      Sightings tell the intel community an indicator was seen in Australia. They are attributed to an anonymised sector identity: customer identity is never shared unless that customer&apos;s sharing policy explicitly says so, and nothing above the policy&apos;s TLP ceiling leaves the tenant.
    </p>
  );
  if (!can(ctx, "intel:share")) {
    return (
      <Card>
        <CardHeader><CardTitle>Sightings feedback</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {privacy}
          <EmptyState title="Sharing requires the intel:share permission">A SOC manager reviews and shares sightings back to OpenCTI.</EmptyState>
        </CardContent>
      </Card>
    );
  }
  const rows = await sightingQueue(ctx);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Sightings feedback</CardTitle>
        <span className="text-xs text-muted">Confirmed malicious matches</span>
      </CardHeader>
      <div className="border-b border-border px-4 py-2.5">{privacy}</div>
      {rows.length === 0 ? (
        <div className="p-4"><EmptyState title="Nothing to share">No confirmed malicious matches are waiting for feedback.</EmptyState></div>
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Indicator</TH>
              <TH>Customer</TH>
              <TH>Matched</TH>
              <TH>Status</TH>
              <TH><span className="sr-only">Share</span></TH>
            </TR>
          </THead>
          <TBody>
            {rows.map((m) => {
              const st = SIGHTING_STATUS[m.sightingStatus] ?? { label: m.sightingStatus, variant: "default" as const };
              return (
                <TR key={m.id}>
                  <TD className="max-w-xs">
                    <div className="truncate font-mono text-xs" title={m.summary.observable.value}>{m.summary.observable.value}</div>
                    <div className="text-[11px] text-muted">{m.summary.observable.type} · {m.summary.entityType}</div>
                  </TD>
                  <TD className="text-sm">{m.tenantName}</TD>
                  <TD className="text-xs text-muted whitespace-nowrap">{fmtDateTime(m.matchedAt)}</TD>
                  <TD><Badge variant={st.variant}>{st.label}</Badge></TD>
                  <TD className="text-right">
                    {m.sightingStatus === "not_shared" || m.sightingStatus === "blocked_by_policy" ? <ShareSightingButton matchId={m.id} /> : null}
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
    </Card>
  );
}

async function Feeds({ ctx }: { ctx: AccessContext }) {
  const feeds = await listFeeds(ctx);
  const canManage = can(ctx, "settings:manage");
  const customers = ctx.tenants.filter((t) => t.kind === "customer").map((t) => ({ id: t.id, name: t.name }));
  return (
    <Card>
      <CardHeader>
        <CardTitle>Intel feeds</CardTitle>
        <span className="text-xs text-muted">{canManage ? "Changes are audited" : "Read only: settings:manage is required to change feeds"}</span>
      </CardHeader>
      {feeds.length === 0 ? (
        <div className="p-4"><EmptyState title="No feeds catalogued">Feeds are connected to OpenCTI and catalogued here with their licensing constraints.</EmptyState></div>
      ) : (
        <div className="divide-y divide-border">
          {feeds.map((f) => (
            <div key={f.key} className={cn("grid gap-3 px-4 py-3 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_auto]", !f.enabled && "opacity-70")}>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">{f.name}</span>
                  <Badge variant="outline">{f.category}</Badge>
                  {f.commercial ? <Badge variant="warn">Commercial</Badge> : <Badge variant="ok">Open</Badge>}
                </div>
                {f.notes ? <p className="mt-1 text-xs text-muted">{f.notes}</p> : null}
              </div>
              <div>
                <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Licence</div>
                <div className="text-sm font-medium">{f.license}</div>
              </div>
              <FeedToggle feedKey={f.key} name={f.name} enabled={f.enabled} canManage={canManage} />
              {f.commercial ? (
                <div className="lg:col-span-3">
                  <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-faint">Customer entitlements (licensed use only)</div>
                  <EntitlementToggles feedKey={f.key} feedName={f.name} tenants={customers} entitled={f.entitledTenants} canManage={canManage} />
                </div>
              ) : null}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
