import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, PageHeader, SeverityBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { requireAccess } from "@/lib/auth/session";
import { attackCoverage, listRules, type CoverageCell } from "@/lib/services/detections";
import { cn } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { ScrollTo } from "./scroll-to";

export const metadata = { title: "ATT&CK coverage" };

/** Enterprise kill-chain order. */
const TACTICS = [
  ["reconnaissance", "Reconnaissance"],
  ["resource-development", "Resource Development"],
  ["initial-access", "Initial Access"],
  ["execution", "Execution"],
  ["persistence", "Persistence"],
  ["privilege-escalation", "Privilege Escalation"],
  ["defense-evasion", "Defence Evasion"],
  ["credential-access", "Credential Access"],
  ["discovery", "Discovery"],
  ["lateral-movement", "Lateral Movement"],
  ["collection", "Collection"],
  ["command-and-control", "Command and Control"],
  ["exfiltration", "Exfiltration"],
  ["impact", "Impact"],
] as const;

const observed = (c: CoverageCell) => c.alerts + c.incidents > 0;
const coverage = (c: CoverageCell) => (c.deployed > 0 ? "deployed" : c.rules > 0 ? "rules" : "none");
const TONE = {
  deployed: "border-ok/50 bg-ok/12",
  rules: "border-sev-medium/50 bg-sev-medium/10",
  none: "border-border bg-surface-2/40",
} as const;

export default async function AttackCoveragePage({ searchParams }: { searchParams: Promise<{ t?: string }> }) {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const ws = await currentWorkspace(ctx);
  const sp = await searchParams;
  const selectedId = sp.t?.trim().toUpperCase() || null;

  const cells = await attackCoverage(ctx, ws.tenantIds);
  const byId = new Map(cells.map((c) => [c.id, c]));
  const selected = selectedId ? byId.get(selectedId) ?? null : null;
  const rules = selected ? (await listRules(ctx)).filter(({ rule }) => rule.attackTechniques.some((t) => t === selected.id || t.startsWith(`${selected.id}.`))) : [];

  // A parent's counts include its sub-techniques; score observed parents only when no sub-technique explains them.
  const observedLeaves = cells.filter((c) => observed(c) && !cells.some((s) => s.parentId === c.id && observed(s)));
  const covered = observedLeaves.filter((c) => c.deployed > 0);
  const gaps = observedLeaves.filter((c) => c.deployed === 0).sort((a, b) => b.incidents - a.incidents || b.alerts - a.alerts);
  const pct = observedLeaves.length ? Math.round((covered.length / observedLeaves.length) * 100) : null;
  const scope = ws.tenant ? ws.tenant.name : "all customers";

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect"
        title="MITRE ATT&CK coverage"
        description={`Detections available and deployed against techniques observed in ${scope} (alerts: last 90 days). Switch customer with the workspace selector.`}
        actions={<Link href="/detections" className="text-sm text-accent hover:underline">Detection rules →</Link>}
      />

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <Card>
          <CardHeader><CardTitle>Observed techniques with deployed detections</CardTitle></CardHeader>
          <CardContent>
            {pct == null ? (
              <p className="text-sm text-muted">No ATT&CK-mapped activity observed in {scope}.</p>
            ) : (
              <>
                <div className={cn("num text-3xl font-semibold", pct >= 80 ? "text-ok" : pct >= 50 ? "text-sev-medium" : "text-sev-critical")}>{pct}%</div>
                <p className="mt-1 text-sm text-muted">{covered.length} of {observedLeaves.length} observed techniques have an active deployment in {scope}.</p>
              </>
            )}
            <Legend />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Observed but not deployed</CardTitle>
            <span className="text-xs text-muted">{gaps.length} gap{gaps.length === 1 ? "" : "s"}, by incidents then alerts</span>
          </CardHeader>
          {gaps.length === 0 ? (
            <div className="p-4 text-sm text-muted">{pct == null ? "Nothing observed yet." : "Every observed technique has a deployed detection."}</div>
          ) : (
            <div className="grid max-h-56 divide-y divide-border overflow-y-auto">
              {gaps.map((g) => (
                <Link key={g.id} href={`/detections/attack?t=${g.id}`} className="flex items-center gap-3 px-4 py-2 hover:bg-surface-2/60">
                  <span className="w-20 shrink-0 font-mono text-xs text-muted">{g.id}</span>
                  <span className="min-w-0 flex-1 truncate text-sm">{g.name}</span>
                  {g.rules > 0 ? <Badge variant="warn">{g.rules} rule{g.rules === 1 ? "" : "s"} ready to deploy</Badge> : <Badge variant="danger">No rule</Badge>}
                  <Counts alerts={g.alerts} incidents={g.incidents} />
                </Link>
              ))}
            </div>
          )}
        </Card>
      </section>

      <div className={cn("grid gap-5", selectedId && "xl:grid-cols-[minmax(0,1fr)_320px]")}>
        <Card className="min-w-0">
          {cells.length === 0 ? (
            <div className="p-4"><EmptyState title="ATT&CK catalogue not loaded">Import the MITRE ATT&CK Enterprise bundle to populate the matrix.</EmptyState></div>
          ) : (
            <div className="overflow-x-auto">
              <div className="grid min-w-max grid-flow-col auto-cols-[11.5rem] gap-2 p-3" role="region" aria-label="ATT&CK coverage matrix">
                {TACTICS.map(([key, label]) => {
                  const inTactic = cells.filter((c) => c.tactics.includes(key));
                  const parents = inTactic.filter((c) => !c.parentId || !inTactic.some((p) => p.id === c.parentId)).sort((a, b) => a.name.localeCompare(b.name));
                  return (
                    <div key={key} className="space-y-1.5">
                      <div className="sticky top-0 border-b border-border pb-1.5">
                        <div className="text-[11px] font-semibold uppercase tracking-wider text-fg">{label}</div>
                        <div className="text-[10.5px] text-faint">{parents.length} techniques</div>
                      </div>
                      {parents.map((p) => (
                        <div key={p.id} className="space-y-1">
                          <Cell cell={p} selected={p.id === selectedId} />
                          {inTactic
                            .filter((s) => s.parentId === p.id)
                            .sort((a, b) => a.id.localeCompare(b.id))
                            .map((s) => (
                              <div key={s.id} className="ml-3 border-l border-border pl-1.5">
                                <Cell cell={s} selected={s.id === selectedId} sub />
                              </div>
                            ))}
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </Card>

        {selectedId ? (
          <aside className="xl:sticky xl:top-4 xl:self-start">
            <Card>
              <CardHeader>
                <CardTitle className="min-w-0">
                  <span className="font-mono text-xs text-muted">{selectedId}</span>
                  {selected ? <span className="block truncate">{selected.name}</span> : null}
                </CardTitle>
                <Link href="/detections/attack" className="text-xs text-muted hover:text-fg" aria-label="Close technique panel">Close</Link>
              </CardHeader>
              {!selected ? (
                <CardContent><p className="text-sm text-muted">{selectedId} is not in the loaded ATT&CK catalogue.</p></CardContent>
              ) : (
                <CardContent className="space-y-4">
                  {selected.parentId ? <Link href={`/detections/attack?t=${selected.parentId}`} className="text-xs text-accent hover:underline">Parent: {selected.parentId} {byId.get(selected.parentId)?.name}</Link> : null}
                  <dl className="grid grid-cols-2 gap-2 text-sm">
                    <Stat label="Rules (enabled)" value={selected.rules} />
                    <Stat label="Active deployments" value={selected.deployed} tone={selected.deployed ? "ok" : observed(selected) ? "danger" : undefined} />
                    <Stat label="Alerts (90 days)" value={selected.alerts} href={`/soc/alerts?technique=${selected.id}`} />
                    <Stat label="Incidents" value={selected.incidents} href="/soc/incidents" />
                  </dl>
                  <div>
                    <h4 className="mb-1.5 text-xs font-medium uppercase tracking-wider text-faint">Detection rules</h4>
                    {rules.length === 0 ? (
                      <p className="text-sm text-muted">No rules map to this technique. <Link href="/detections/new" className="text-accent hover:underline">Write one</Link>.</p>
                    ) : (
                      <ul className="divide-y divide-border rounded-md border border-border">
                        {rules.map(({ rule, deployments }) => (
                          <li key={rule.id}>
                            <Link href={`/detections/rules/${rule.id}`} className="block px-3 py-2 hover:bg-surface-2/60">
                              <div className="truncate text-sm font-medium">{rule.title}</div>
                              <div className="mt-0.5 flex items-center gap-2 text-[11px] text-muted">
                                <SeverityBadge severity={rule.severity} />
                                <span>{deployments} deployment{deployments === 1 ? "" : "s"}</span>
                                {!rule.enabled ? <Badge variant="outline">disabled</Badge> : null}
                              </div>
                            </Link>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </CardContent>
              )}
            </Card>
          </aside>
        ) : null}
      </div>
      {selected ? <ScrollTo id={`tech-${selected.id}`} /> : null}
    </div>
  );
}

function Cell({ cell, selected, sub }: { cell: CoverageCell; selected: boolean; sub?: boolean }) {
  const cov = coverage(cell);
  const gap = cov !== "deployed" && observed(cell);
  const status = cov === "deployed" ? "deployed" : cov === "rules" ? "rules available, not deployed" : "no detection";
  return (
    <Link
      id={`tech-${cell.id}`}
      href={`/detections/attack?t=${cell.id}`}
      aria-current={selected ? "true" : undefined}
      aria-label={`${cell.id} ${cell.name}: ${status}; ${cell.alerts} alerts, ${cell.incidents} incidents`}
      className={cn(
        "block rounded border px-2 py-1.5 transition-colors hover:border-accent",
        TONE[cov],
        gap && "ring-1 ring-sev-critical/60",
        selected && "outline-2 outline-offset-1 outline-accent",
      )}
    >
      <div className="flex items-baseline justify-between gap-1">
        <span className="font-mono text-[10px] text-muted">{cell.id}</span>
        <Counts alerts={cell.alerts} incidents={cell.incidents} />
      </div>
      <div className={cn("leading-tight", sub ? "text-[11px] text-muted" : "text-xs text-fg")}>{cell.name}</div>
    </Link>
  );
}

function Counts({ alerts, incidents }: { alerts: number; incidents: number }) {
  if (!alerts && !incidents) return null;
  return (
    <span className="inline-flex shrink-0 gap-1">
      {alerts ? <span className="num rounded bg-sev-high/15 px-1 text-[10px] font-semibold text-sev-high" title={`${alerts} alerts`}>{alerts}A</span> : null}
      {incidents ? <span className="num rounded bg-danger/15 px-1 text-[10px] font-semibold text-danger" title={`${incidents} incidents`}>{incidents}I</span> : null}
    </span>
  );
}

function Stat({ label, value, href, tone }: { label: string; value: number; href?: string; tone?: "ok" | "danger" }) {
  const body = (
    <>
      <dt className="text-[11px] uppercase tracking-wider text-faint">{label}</dt>
      <dd className={cn("num text-lg font-semibold", tone === "ok" ? "text-ok" : tone === "danger" ? "text-sev-critical" : "text-fg")}>{value}</dd>
    </>
  );
  return href ? (
    <Link href={href} className="rounded-md border border-border px-2.5 py-2 hover:border-border-strong">{body}</Link>
  ) : (
    <div className="rounded-md border border-border px-2.5 py-2">{body}</div>
  );
}

function Legend() {
  return (
    <ul className="mt-4 space-y-1.5 border-t border-border pt-3 text-xs text-muted" aria-label="Legend">
      <li className="flex items-center gap-2"><span className={cn("size-3 rounded-sm border", TONE.deployed)} />Deployed detection</li>
      <li className="flex items-center gap-2"><span className={cn("size-3 rounded-sm border", TONE.rules)} />Rule available, not deployed</li>
      <li className="flex items-center gap-2"><span className={cn("size-3 rounded-sm border", TONE.none)} />No detection</li>
      <li className="flex items-center gap-2"><span className="size-3 rounded-sm border border-border ring-1 ring-sev-critical/60" />Observed without a deployed detection</li>
      <li className="flex items-center gap-2"><span className="num rounded bg-sev-high/15 px-1 text-[10px] font-semibold text-sev-high">3A</span>alerts<span className="num ml-2 rounded bg-danger/15 px-1 text-[10px] font-semibold text-danger">1I</span>incidents</li>
    </ul>
  );
}
