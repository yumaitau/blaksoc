import { ChevronRight } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, PageHeader, RiskFactors, RiskScore, StatLink } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { RiskFactor } from "@/db/schema";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { patchPriorities, vulnerabilityDetail, vulnSummary } from "@/lib/services/vulnerabilities";
import { cn } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { VulnInstances } from "./vuln-instances";

export const metadata = { title: "Vulnerabilities" };

const CVE = /^CVE-\d{4}-\d{4,}$/i;
const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim() || undefined;
const pct = (n: number | null | undefined) => (n == null ? "—" : `${(n * 100).toFixed(n < 0.01 ? 2 : 1)}%`);

/** "What should this customer patch first?" Ranked by blakSOC priority, grouped per CVE per customer. */
export default async function VulnerabilitiesPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const ctx = await requireAccess();
  if (!can(ctx, "vuln:read")) redirect("/portal");
  const sp = await searchParams;
  const ws = await currentWorkspace(ctx);
  const tenantParam = one(sp.tenant);
  const tenant = tenantParam && ctx.tenantIds.includes(tenantParam) ? tenantParam : undefined;
  const tenantIds = tenant ? [tenant] : ws.tenantIds;
  const kevOnly = one(sp.kev) === "1";
  const cveParam = one(sp.cve);
  const cve = cveParam && CVE.test(cveParam) ? cveParam.toUpperCase() : undefined;

  const [summary, all] = await Promise.all([vulnSummary(ctx, tenantIds), patchPriorities(ctx, { tenantIds, kevOnly })]);
  const rows = cve ? all.filter((r) => r.cve === cve) : all;
  const detailTenant = cve ? (tenant ?? (new Set(rows.map((r) => r.tenantId)).size === 1 ? rows[0]!.tenantId : undefined)) : undefined;
  const detail = cve && detailTenant ? await vulnerabilityDetail(ctx, detailTenant, cve) : null;
  const multiTenant = new Set(all.map((r) => r.tenantId)).size > 1 || tenantIds.length > 1;

  const qs = (p: Record<string, string | undefined>) => {
    const u = new URLSearchParams();
    for (const [k, v] of Object.entries({ tenant, kev: kevOnly ? "1" : undefined, ...p })) if (v) u.set(k, v);
    const s = u.toString();
    return s ? `/vulnerabilities?${s}` : "/vulnerabilities";
  };
  const scope = tenant ? (ctx.tenants.find((t) => t.id === tenant)?.name ?? "this customer") : ws.tenant?.name ?? "all customers";

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Investigate"
        title="What should be patched first?"
        description={`Patch priorities for ${scope}. Ranked by blakSOC priority: exploitation evidence (CISA KEV, EPSS, OpenCTI threats), asset criticality and exposure. Not CVSS alone.`}
      />

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatLink label="Open vulnerabilities" value={summary.open} href={qs({ kev: undefined })} hint="All priorities" />
        <StatLink label="Known exploited (KEV)" value={summary.kev} href={qs({ kev: "1" })} tone={summary.kev ? "danger" : "ok"} hint="Patch first" />
        <StatLink label="Urgent (priority 70+)" value={summary.urgent} href={qs({})} tone={summary.urgent ? "warn" : "ok"} hint="Top of list" />
        <StatLink label="Critical assets affected" value={summary.criticalAssetsAffected} href={`/assets?minCriticality=4${tenant ? `&tenant=${tenant}` : ""}`} tone={summary.criticalAssetsAffected ? "warn" : "ok"} hint="View assets" />
      </section>

      {cve ? (
        <Card>
          <CardHeader>
            <div>
              <CardTitle className="font-mono">{cve}</CardTitle>
              <p className="mt-0.5 text-xs text-muted">{detailTenant ? ctx.tenants.find((t) => t.id === detailTenant)?.name : "Choose a customer below to manage instances."}</p>
            </div>
            <Link href={qs({ cve: undefined })} className="text-xs text-accent hover:underline">Close</Link>
          </CardHeader>
          {detail ? (
            <>
              <CardContent className="grid gap-4 border-b border-border md:grid-cols-4">
                <div className="md:col-span-2">
                  <div className="text-[11px] uppercase tracking-wider text-faint">Summary</div>
                  <p className="mt-1 text-sm">{detail.intel?.summary ?? detail.instances[0]?.vuln.title ?? "No description available."}</p>
                </div>
                <div className="space-y-1 text-sm">
                  <div><span className="text-muted">CVSS </span><span className="num font-semibold">{detail.intel?.cvss ?? detail.instances[0]?.vuln.cvss ?? "—"}</span></div>
                  <div><span className="text-muted">EPSS </span><span className="num font-semibold">{pct(detail.intel?.epss)}</span>{detail.intel?.epssPercentile != null ? <span className="text-xs text-muted"> (percentile {pct(detail.intel.epssPercentile)})</span> : null}</div>
                </div>
                <div className="space-y-1 text-sm">
                  {detail.intel?.kev ? (
                    <>
                      <Badge variant="danger">CISA KEV</Badge>
                      <div className="text-xs text-muted">Added {detail.intel.kevDateAdded ?? "—"} · due {detail.intel.kevDueDate ?? "—"}</div>
                      {detail.intel.kevRansomware ? <Badge variant="danger">Known ransomware use</Badge> : null}
                    </>
                  ) : (
                    <span className="text-xs text-muted">Not in CISA KEV</span>
                  )}
                  {detail.intel?.openctiRefs.length ? <OpenctiRefs refs={detail.intel.openctiRefs} linked={ctx.isPlatform} /> : null}
                </div>
              </CardContent>
              {detail.instances.length === 0 ? (
                <div className="p-4 text-sm text-muted">No instances of this CVE for this customer.</div>
              ) : (
                <VulnInstances
                  canWrite={can(ctx, "vuln:write", detailTenant!)}
                  rows={detail.instances.map((i) => ({
                    id: i.vuln.id, assetId: i.vuln.assetId, assetName: i.assetName, criticality: i.criticality, exposure: i.exposure,
                    packageName: i.vuln.packageName, packageVersion: i.vuln.packageVersion, fixedVersion: i.vuln.fixedVersion,
                    status: i.vuln.status, priorityScore: i.vuln.priorityScore, lastSeen: i.vuln.lastSeen.toISOString(),
                  }))}
                />
              )}
            </>
          ) : null}
        </Card>
      ) : null}

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-muted">Show:</span>
        <Link href={qs({ kev: undefined, cve })} className={cn("rounded-md border px-2.5 py-1", !kevOnly ? "border-accent text-accent" : "border-border text-muted hover:text-fg")}>All open</Link>
        <Link href={qs({ kev: "1", cve })} className={cn("rounded-md border px-2.5 py-1", kevOnly ? "border-accent text-accent" : "border-border text-muted hover:text-fg")}>Known exploited only</Link>
        <span className="ml-auto text-xs text-muted">{rows.length} CVE group{rows.length === 1 ? "" : "s"}</span>
      </div>

      <Card>
        {rows.length === 0 ? (
          <div className="p-4"><EmptyState title={kevOnly ? "No known-exploited vulnerabilities" : "Nothing to patch"}>{kevOnly ? "No open CVEs in scope are on the CISA KEV list." : "No open vulnerabilities in scope."}</EmptyState></div>
        ) : (
          <ol className="divide-y divide-border">
            {rows.map((r, idx) => {
              const factors = (Array.isArray(r.factors) ? r.factors : []) as RiskFactor[];
              const active = r.cve === cve && r.tenantId === detailTenant;
              return (
                <li key={`${r.tenantId}:${r.cve}`} className={cn(active && "bg-accent-soft/40")}>
                  <div className="grid grid-cols-[2rem_5.5rem_1fr_auto] items-start gap-3 px-4 py-3">
                    <span className="num pt-0.5 text-right text-xs text-faint">{idx + 1}</span>
                    <RiskScore score={r.maxPriority} />
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Link href={qs({ cve: r.cve, tenant: r.tenantId })} className="font-mono text-sm font-semibold hover:text-accent">{r.cve}</Link>
                        {r.kev ? <Badge variant="danger">KEV{r.kevDueDate ? ` · due ${r.kevDueDate}` : ""}</Badge> : null}
                        {r.kevRansomware ? <Badge variant="danger">ransomware</Badge> : null}
                        {multiTenant ? <Badge variant="outline">{r.tenantName}</Badge> : null}
                      </div>
                      <div className="mt-0.5 truncate text-sm text-muted">{r.title ?? r.packages.filter(Boolean).join(", ")}</div>
                      <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
                        <span><span className="num font-semibold text-fg">{r.affectedAssets}</span> asset{r.affectedAssets === 1 ? "" : "s"}</span>
                        <span className={cn(r.criticalAssets && "text-sev-high")}><span className="num font-semibold">{r.criticalAssets}</span> critical</span>
                        <span className={cn(r.internetFacing && "text-sev-critical")}><span className="num font-semibold">{r.internetFacing}</span> internet-facing</span>
                        <span>EPSS <span className="num font-semibold text-fg">{pct(r.epss)}</span></span>
                        {r.cvss != null ? <span>CVSS <span className="num font-semibold text-fg">{r.cvss}</span></span> : null}
                        {r.openctiRefs?.length ? <OpenctiRefs refs={r.openctiRefs} linked={ctx.isPlatform} /> : null}
                      </div>
                    </div>
                    <Link href={qs({ cve: r.cve, tenant: r.tenantId })} className="inline-flex items-center gap-1 whitespace-nowrap pt-0.5 text-xs text-accent hover:underline">
                      Instances <ChevronRight className="size-3.5" />
                    </Link>
                  </div>
                  {factors.length ? (
                    <details className="group px-4 pb-3 pl-[8.5rem]">
                      <summary className="cursor-pointer select-none text-xs text-muted hover:text-fg">Why this priority</summary>
                      <div className="mt-2 max-w-2xl rounded-md border border-border bg-bg/40 p-3">
                        <RiskFactors factors={factors} total={r.maxPriority} />
                      </div>
                    </details>
                  ) : null}
                </li>
              );
            })}
          </ol>
        )}
      </Card>
      <p className="text-xs text-faint">KEV due dates are CISA federal deadlines, shown as a signal of urgency.</p>
    </div>
  );
}

function OpenctiRefs({ refs, linked }: { refs: { id: string; name: string; type: string }[]; linked: boolean }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {refs.slice(0, 3).map((t) =>
        linked ? (
          <Link key={t.id} href={`/intel?q=${encodeURIComponent(t.name)}`} title={t.type}><Badge variant="intel">{t.name}</Badge></Link>
        ) : (
          <Badge key={t.id} variant="intel" title={t.type}>{t.name}</Badge>
        ),
      )}
      {refs.length > 3 ? <span className="text-[11px] text-faint">+{refs.length - 3}</span> : null}
    </span>
  );
}
