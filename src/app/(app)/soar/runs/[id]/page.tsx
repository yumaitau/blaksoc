import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader, StatusBadge } from "@/components/soc/indicators";
import { HumanApprovalBadge } from "@/components/soar/flow";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { requireAccess } from "@/lib/auth/session";
import { getRun } from "@/lib/services/playbooks";
import { stepCatalogue } from "@/lib/soar/engine";
import { fmtDateTime, timeAgo } from "@/lib/utils";

export const metadata = { title: "Playbook run" };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function duration(a: Date, b: Date | null) {
  if (!b) return null;
  const s = Math.max(0, Math.round((b.getTime() - a.getTime()) / 1000));
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.round(s / 60)}m` : `${(s / 3600).toFixed(1)}h`;
}

export default async function RunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const ctx = await requireAccess();
  const run = await getRun(ctx, id);
  if (!run) notFound();
  const catalogue = stepCatalogue();
  const defs = new Map(run.playbookSteps.map((s) => [s.id, s]));
  const gate = new Map(run.approvals.map((a) => [a.id, a]));
  const sameVersion = run.playbookVersion === run.currentVersion;
  const done = new Set(run.steps.map((s) => s.stepId));
  const remaining = run.stepsPinned || sameVersion ? run.playbookSteps.filter((s) => !done.has(s.id)) : [];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Playbook run"
        title={run.playbookName}
        description={`${run.tenantName} · triggered by ${String((run.trigger as { event?: string }).event ?? "unknown")} · started ${fmtDateTime(run.startedAt)}`}
        actions={<Link href="/soar/runs" className="text-sm text-accent hover:underline">← All runs</Link>}
      />

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Fact label="Status"><StatusBadge status={run.status} /></Fact>
        <Fact label="Playbook"><Link href={`/soar/playbooks/${run.playbookId}`} className="text-accent hover:underline">v{run.playbookVersion}</Link>{!sameVersion ? <span className="ml-1.5 text-[11px] text-faint">(now v{run.currentVersion})</span> : null}</Fact>
        <Fact label="Duration">{duration(run.startedAt, run.finishedAt) ?? <span className="text-muted">in progress</span>}</Fact>
        <Fact label="Alert">{run.alertId ? <Link href={`/soc/alerts/${run.alertId}`} className="block truncate text-accent hover:underline" title={run.alertTitle ?? undefined}>{run.alertTitle ?? run.alertId.slice(0, 8)}</Link> : "—"}</Fact>
        <Fact label="Incident">{run.incidentId ? <Link href={`/soc/incidents/${run.incidentId}`} className="text-accent hover:underline">Open incident →</Link> : "—"}</Fact>
      </section>

      {run.error ? <div role="alert" className="rounded-md border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger">{run.error}</div> : null}

      <Card>
        <CardHeader><CardTitle>Steps</CardTitle><span className="text-xs text-muted">{run.steps.length} executed{remaining.length ? ` · ${remaining.length} not reached` : ""}</span></CardHeader>
        <ol className="divide-y divide-border">
          {run.steps.map((s, i) => {
            const def = defs.get(s.stepId);
            const ap = s.approvalId ? gate.get(s.approvalId) : undefined;
            const destructive = catalogue.find((c) => c.key === s.action)?.destructive;
            return (
              <li key={s.id} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="num w-6 text-sm font-semibold text-faint">{i + 1}.</span>
                  <span className="text-sm font-medium">{def?.name ?? s.stepId}</span>
                  <span className="font-mono text-[11px] text-muted">{s.action}</span>
                  {destructive ? <HumanApprovalBadge /> : null}
                  <span className="ml-auto flex items-center gap-2 text-xs text-muted">
                    <span title={fmtDateTime(s.startedAt)}>{timeAgo(s.startedAt)}</span>
                    {duration(s.startedAt, s.finishedAt) ? <span>· {duration(s.startedAt, s.finishedAt)}</span> : null}
                    <StatusBadge status={s.status} />
                  </span>
                </div>
                <div className="ml-8 mt-1.5 space-y-1.5">
                  {s.error ? <p className="text-sm text-danger">{s.error}</p> : null}
                  {ap ? (
                    <p className="flex flex-wrap items-center gap-2 text-sm">
                      <span className="text-muted">Approval gate:</span> {ap.summary} <StatusBadge status={ap.status} />
                      {ap.decidedAt ? <span className="text-xs text-muted">decided {fmtDateTime(ap.decidedAt)}{ap.decisionNote ? ` · “${ap.decisionNote}”` : ""}</span> : null}
                      <Link href="/soc/approvals" className="text-xs text-accent hover:underline">{ap.status === "PENDING" ? "Decide in approvals →" : "Approvals →"}</Link>
                    </p>
                  ) : null}
                  {s.output != null ? (
                    <details>
                      <summary className="cursor-pointer text-xs text-muted hover:text-fg">Output</summary>
                      <pre className="mt-1 max-h-72 overflow-auto rounded-md border border-border bg-bg p-2 font-mono text-[11px] leading-relaxed">{JSON.stringify(s.output, null, 2)}</pre>
                    </details>
                  ) : null}
                </div>
              </li>
            );
          })}
          {remaining.map((s) => (
            <li key={`pending-${s.id}`} className="flex flex-wrap items-center gap-2 px-4 py-3 opacity-60">
              <span className="w-6" />
              <span className="text-sm">{s.name}</span>
              <span className="font-mono text-[11px] text-muted">{s.action}</span>
              <Badge variant="outline" className="ml-auto">{run.status === "RUNNING" || run.status === "WAITING_APPROVAL" ? "Pending" : "Not reached"}</Badge>
            </li>
          ))}
          {!run.steps.length && !remaining.length ? <li className="px-4 py-3 text-sm text-muted">No steps recorded yet.</li> : null}
        </ol>
      </Card>

      {run.responseActions.length ? (
        <Card>
          <CardHeader><CardTitle>Response actions</CardTitle><Link href="/soc/approvals" className="text-xs text-accent hover:underline">Approvals →</Link></CardHeader>
          <Table>
            <THead><TR className="hover:bg-transparent"><TH>Action</TH><TH>Target</TH><TH>Status</TH><TH>Requested</TH><TH>Executed</TH></TR></THead>
            <TBody>
              {run.responseActions.map((a) => (
                <TR key={a.id}>
                  <TD>{catalogue.find((c) => c.key === a.action)?.label ?? a.action}{a.destructive ? <Badge variant="warn" className="ml-2">destructive</Badge> : null}</TD>
                  <TD className="font-mono text-xs text-muted">{Object.entries(a.target).filter(([, v]) => v != null).map(([k, v]) => `${k}=${String(v)}`).join(" ") || "—"}</TD>
                  <TD><StatusBadge status={a.status} /></TD>
                  <TD className="text-xs text-muted">{fmtDateTime(a.createdAt)}</TD>
                  <TD className="text-xs text-muted">{fmtDateTime(a.executedAt)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </Card>
      ) : null}

      <Card>
        <CardHeader><CardTitle>Trigger payload</CardTitle></CardHeader>
        <CardContent><pre className="overflow-auto font-mono text-[11px] text-muted">{JSON.stringify(run.trigger, null, 2)}</pre></CardContent>
      </Card>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg border border-border bg-surface px-4 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</div>
      <div className="mt-1 text-sm">{children}</div>
    </div>
  );
}
