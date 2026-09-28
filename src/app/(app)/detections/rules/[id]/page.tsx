import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { AttackChips, EmptyState, PageHeader, SeverityBadge, StatusBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { authorNames, getRule } from "@/lib/services/detections";
import { fmtDateTime } from "@/lib/utils";
import { DeployPanel, RuleEditor, RuleEnabledToggle, TestResultsTable, TestRunner } from "../../rule-controls";

export const metadata = { title: "Detection rule" };

const EXAMPLE_CASES = JSON.stringify(
  [
    { name: "Malicious sample should match", event: { Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: "powershell.exe -enc JABzAD0A" }, expect: true },
    { name: "Benign admin activity should not match", event: { Image: "C:\\Windows\\explorer.exe", CommandLine: "explorer.exe" }, expect: false },
  ],
  null,
  2,
);

export default async function RulePage({ params }: { params: Promise<{ id: string }> }) {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) notFound();
  const data = await getRule(ctx, id);
  if (!data) notFound();
  const { rule, versions, tests, deployments } = data;
  const current = versions.find((v) => v.version === rule.currentVersion) ?? versions[0];
  const names = await authorNames(ctx, [...versions.map((v) => v.createdBy), ...tests.map((t) => t.ranBy), ...deployments.map((d) => d.deployedBy)]);
  const tenantName = new Map(ctx.tenants.map((t) => [t.id, t.name]));

  const canWrite = rule.tenantId ? can(ctx, "detection:write", rule.tenantId) : can(ctx, "detection:write");
  const deployTargets = ctx.tenants
    .filter((t) => t.kind === "customer" && (!rule.tenantId || t.id === rule.tenantId) && can(ctx, "detection:deploy", t.id))
    .map((t) => ({ id: t.id, name: t.name, deployedVersion: deployments.find((d) => d.tenantId === t.id && d.status === "active")?.version ?? null }));
  const lastTest = tests[0];
  const logsource = Object.entries(rule.logsource);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={rule.tenantId ? `Customer rule · ${tenantName.get(rule.tenantId) ?? "customer"}` : "Global rule"}
        title={rule.title}
        description={rule.description ?? undefined}
        actions={
          <>
            <span className="text-xs text-muted">Enabled</span>
            <RuleEnabledToggle id={rule.id} title={rule.title} enabled={rule.enabled} canWrite={canWrite} />
            <Link href="/detections" className="ml-3 text-sm text-accent hover:underline">← All rules</Link>
          </>
        }
      />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Rule workspace</CardTitle>
            <span className="text-xs text-muted">Current v{rule.currentVersion}{current ? ` · ${current.sha256.slice(0, 12)}` : ""}</span>
          </CardHeader>
          <CardContent>
            <RuleEditor key={rule.currentVersion} ruleId={rule.id} initialYaml={current?.yaml ?? ""} initialConfidence={rule.confidence} canWrite={canWrite} />
          </CardContent>
        </Card>

        <Card className="self-start">
          <CardHeader><CardTitle>Metadata</CardTitle><span className="text-xs text-muted">From the current version</span></CardHeader>
          <CardContent>
            <dl className="space-y-3 text-sm">
              <div className="flex items-center justify-between gap-3"><dt className="text-muted">Severity</dt><dd><SeverityBadge severity={rule.severity} /></dd></div>
              <div className="flex items-center justify-between gap-3"><dt className="text-muted">Status</dt><dd><Badge variant={rule.status === "stable" ? "ok" : "default"}>{rule.status}</Badge></dd></div>
              <div className="flex items-center justify-between gap-3"><dt className="text-muted">Confidence</dt><dd className="num font-semibold">{rule.confidence}</dd></div>
              <div className="flex items-center justify-between gap-3"><dt className="text-muted">Sigma id</dt><dd className="truncate font-mono text-xs">{rule.sigmaId}</dd></div>
              <div>
                <dt className="mb-1 text-muted">ATT&CK</dt>
                <dd><AttackChips techniques={rule.attackTechniques} max={12} /></dd>
              </div>
              <div>
                <dt className="mb-1 text-muted">Log source</dt>
                <dd className="flex flex-wrap gap-1">
                  {logsource.length ? logsource.map(([k, v]) => <Badge key={k} variant="outline"><span className="text-faint">{k}:</span> {v}</Badge>) : <span className="text-xs text-faint">—</span>}
                </dd>
              </div>
              <div>
                <dt className="mb-1 text-muted">Known false positives</dt>
                <dd>
                  {rule.falsePositives.length ? (
                    <ul className="list-disc space-y-0.5 pl-4 text-xs">{rule.falsePositives.map((f) => <li key={f}>{f}</li>)}</ul>
                  ) : (
                    <span className="text-xs text-warn">Not documented. Add a falsepositives list so triage knows what benign looks like.</span>
                  )}
                </dd>
              </div>
              <div className="flex items-center justify-between gap-3"><dt className="text-muted">Updated</dt><dd className="text-xs">{fmtDateTime(rule.updatedAt)}</dd></div>
            </dl>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Test runner</CardTitle>
            {lastTest ? <Badge variant={lastTest.passed ? "ok" : "danger"}>Last run v{lastTest.version}: {lastTest.passed ? "passed" : "failed"}</Badge> : <Badge variant="warn">Never tested</Badge>}
          </CardHeader>
          <CardContent className="space-y-5">
            <TestRunner ruleId={rule.id} example={lastTest ? JSON.stringify(lastTest.cases, null, 2) : EXAMPLE_CASES} canRun={canWrite} />
            <div>
              <h4 className="mb-2 text-xs font-medium uppercase tracking-wider text-faint">Test history</h4>
              {tests.length === 0 ? (
                <p className="text-sm text-muted">No test runs recorded.</p>
              ) : (
                <div className="divide-y divide-border rounded-md border border-border">
                  {tests.map((t) => (
                    <details key={t.id} className="group">
                      <summary className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-surface-2/60">
                        <Badge variant={t.passed ? "ok" : "danger"}>{t.passed ? "Pass" : "Fail"}</Badge>
                        <span className="num text-xs text-muted">v{t.version}</span>
                        <span className="text-xs text-muted">{t.results.filter((r) => r.pass).length}/{t.results.length} cases</span>
                        <span className="ml-auto text-xs text-muted">{names.get(t.ranBy ?? "") ?? "—"} · {fmtDateTime(t.createdAt)}</span>
                      </summary>
                      <div className="px-3 pb-3"><TestResultsTable results={t.results} /></div>
                    </details>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Deploy</CardTitle>
            <span className="text-xs text-muted">{rule.tenantId ? "Customer rules deploy only to their own customer" : "Scheduled query per customer"}</span>
          </CardHeader>
          <CardContent className="space-y-5">
            <DeployPanel ruleId={rule.id} customers={deployTargets} canDeploy={can(ctx, "detection:deploy") && deployTargets.length > 0} enabled={rule.enabled} />
            <div>
              <h4 className="mb-2 text-xs font-medium uppercase tracking-wider text-faint">Deployments</h4>
              {deployments.length === 0 ? (
                <EmptyState title="Not deployed">This rule is not running against any customer.</EmptyState>
              ) : (
                <Table>
                  <THead>
                    <TR><TH>Customer</TH><TH className="text-right">Version</TH><TH>Status</TH><TH>Last run</TH><TH className="text-right">Last hits</TH></TR>
                  </THead>
                  <TBody>
                    {deployments.map((d) => (
                      <TR key={d.id}>
                        <TD>
                          <Link href={`/soc/alerts?tenant=${d.tenantId}`} className="text-sm hover:text-accent hover:underline">{tenantName.get(d.tenantId) ?? d.tenantId.slice(0, 8)}</Link>
                          <div className="text-[11px] text-muted">by {names.get(d.deployedBy ?? "") ?? "—"} · {fmtDateTime(d.deployedAt)}</div>
                        </TD>
                        <TD className="num text-right">
                          v{d.version}
                          {d.version < rule.currentVersion ? <Badge variant="warn" className="ml-1.5">behind</Badge> : null}
                        </TD>
                        <TD><StatusBadge status={d.status.toUpperCase()} /></TD>
                        <TD className="text-xs text-muted whitespace-nowrap">{fmtDateTime(d.lastRunAt)}</TD>
                        <TD className="num text-right">{d.lastHitCount ?? "—"}</TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle>Version history</CardTitle><span className="text-xs text-muted">{versions.length} version{versions.length === 1 ? "" : "s"}, immutable</span></CardHeader>
        <div className="divide-y divide-border">
          {versions.map((v) => (
            <details key={v.id} className="group">
              <summary className="grid cursor-pointer grid-cols-[4rem_7rem_minmax(0,1fr)_auto] items-center gap-3 px-4 py-2.5 text-sm hover:bg-surface-2/60">
                <span className="num font-semibold">v{v.version}{v.version === rule.currentVersion ? <span className="ml-1 text-[10px] font-normal text-accent">current</span> : null}</span>
                <span className="font-mono text-xs text-muted" title={v.sha256}>{v.sha256.slice(0, 12)}</span>
                <span className="truncate">{v.changeNote ?? <span className="text-faint">No change note</span>}</span>
                <span className="text-xs text-muted whitespace-nowrap">{names.get(v.createdBy ?? "") ?? "system"} · {fmtDateTime(v.createdAt)}</span>
              </summary>
              <pre className="mx-4 mb-3 max-h-96 overflow-auto rounded-md border border-border bg-bg p-3 font-mono text-[12px] leading-5">{v.yaml}</pre>
            </details>
          ))}
        </div>
      </Card>
    </div>
  );
}
