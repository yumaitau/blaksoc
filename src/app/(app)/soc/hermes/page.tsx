import Link from "next/link";
import { redirect } from "next/navigation";
import { HERMES_NOTE_TITLE, HERMES_TITLE, HermesBadge } from "@/components/soc/hermes-badge";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Markdown } from "@/components/soc/markdown";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { requireAccess } from "@/lib/auth/session";
import { getMemory, isHermesStaff, listReports } from "@/lib/services/hermes";
import { canControlHermes, hermesSwitchState, listTuningActions } from "@/lib/services/tuning";
import { HERMES_KIND_LABEL, hermesActionHref } from "@/lib/tuning/hermes-ui";
import { fmtDateTime, timeAgo } from "@/lib/utils";
import { AddMemoryNoteForm, DeleteNoteButton, HermesSwitch, UndoButton } from "../tuning/controls";

export const metadata = { title: "Hermes" };

/**
 * Hermes, the in-cluster tuning agent: whether it may act, what it reported, what it did (with undo), and
 * what it remembers. Platform staff only; everything that changes here is audited.
 */
export default async function HermesPage() {
  const ctx = await requireAccess();
  if (!isHermesStaff(ctx)) redirect("/soc");
  const [state, reports, actions, memory] = await Promise.all([
    hermesSwitchState(),
    listReports(ctx, 20, "alert:tune"),
    listTuningActions(ctx, undefined, 100),
    getMemory(ctx, "alert:tune"),
  ]);
  const [latest, ...older] = reports;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect & respond"
        title="Hermes"
        description="The AI tuning agent. It sees aggregate patterns only (no titles, hosts, users or customer names) and every action it takes is checked by blakSOC's guardrails, audited and undoable here."
        actions={<Link href="/soc/tuning" className="text-xs text-accent hover:underline">Noise rules →</Link>}
      />

      <Card>
        <CardContent className="space-y-3 py-4">
          <HermesSwitch enabled={state.enabled} canControl={canControlHermes(ctx)} />
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-5">
            <Fact label="Last run">{latest ? <span title={fmtDateTime(latest.createdAt)}>{timeAgo(latest.createdAt)}</span> : "never"}</Fact>
            <Fact label="Executed">{latest?.stats.executed ?? "—"}</Fact>
            <Fact label="Refused by guardrails">{latest?.stats.refused ?? "—"}</Fact>
            <Fact label="Dry runs">{latest?.stats.dryRun ?? "—"}</Fact>
            <Fact label="Patterns reviewed">{latest?.stats.patternsReviewed ?? "—"}</Fact>
          </dl>
          {state.updatedAt ? <p className="text-xs text-faint">Switch last changed {fmtDateTime(state.updatedAt)}.</p> : null}
        </CardContent>
      </Card>

      <section className="grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Latest report</CardTitle>
            {latest ? <span className="text-xs text-muted">{fmtDateTime(latest.periodStart)} – {fmtDateTime(latest.periodEnd)}</span> : null}
          </CardHeader>
          <CardContent>
            {latest ? (
              <>
                <p className="mb-3 flex items-center gap-2 text-[11px] text-muted"><HermesBadge label="Hermes report" title={HERMES_NOTE_TITLE} /> interpretation, not evidence</p>
                <Markdown text={latest.markdown} />
              </>
            ) : (
              <EmptyState title="No reports yet">Hermes posts one after each run.</EmptyState>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Report history</CardTitle></CardHeader>
          {older.length === 0 ? <div className="p-4 text-sm text-muted">No earlier reports.</div> : (
            <div className="divide-y divide-border">
              {older.map((r) => (
                <details key={r.id} className="px-4 py-2">
                  <summary className="cursor-pointer text-sm">
                    {fmtDateTime(r.periodEnd)} <span className="text-xs text-muted">· {r.stats.executed} executed, {r.stats.refused} refused</span>
                  </summary>
                  <div className="mt-2"><Markdown text={r.markdown} /></div>
                </details>
              ))}
            </div>
          )}
        </Card>
      </section>

      <Card>
        <CardHeader><CardTitle>Hermes actions</CardTitle><span className="text-xs text-muted">Closures can be undone until the alerts are purged (7 days at the earliest). Affected counts open the alerts in the queue.</span></CardHeader>
        {actions.length === 0 ? (
          <div className="p-4"><EmptyState title="No actions yet" /></div>
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>When</TH><TH>Action</TH><TH>Customer</TH><TH>Pattern</TH><TH>Reason</TH><TH className="text-right">Affected</TH><TH>Outcome</TH><TH />
              </TR>
            </THead>
            <TBody>
              {actions.map(({ action: a, tenantName, actorName, undoneByName, reopened }) => {
                const href = hermesActionHref(a);
                return (
                  <TR key={a.id}>
                    <TD className="whitespace-nowrap text-xs text-muted" title={fmtDateTime(a.createdAt)}>{timeAgo(a.createdAt)}</TD>
                    <TD className="text-xs">
                      <div className="flex flex-col items-start gap-1">
                        <HermesBadge size="sm" title={`${HERMES_TITLE}${actorName ? ` (service identity “${actorName}”)` : ""}`} />
                        <span>{HERMES_KIND_LABEL[a.kind] ?? a.kind}</span>
                      </div>
                    </TD>
                    <TD className="max-w-36 truncate text-xs text-muted">{tenantName}</TD>
                    <TD className="text-xs"><span className="text-muted">{a.source}</span> <span className="font-mono">{a.ruleId}</span></TD>
                    <TD className="max-w-72 text-xs"><div className="line-clamp-2">{typeof a.params.reason === "string" ? a.params.reason : "—"}</div></TD>
                    <TD className="num text-right text-xs">
                      {href ? <Link href={href} className="text-accent hover:underline" title="Open the alerts this action touched">{a.kind === "annotate" ? "alerts" : a.affectedCount}</Link> : a.affectedCount}
                    </TD>
                    <TD className="text-xs">
                      {a.undoneAt ? <Badge variant="warn">undone{undoneByName ? ` by ${undoneByName}` : ""}</Badge> : reopened ? <Badge variant="warn">{reopened} reopened</Badge> : <Badge variant="ok">standing</Badge>}
                    </TD>
                    <TD>{a.undoneAt ? null : <UndoButton id={a.id} kind={a.kind} />}</TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>

      <section className="grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader><CardTitle>Memory</CardTitle><span className="text-xs text-muted">Version {memory.version} · {memory.notes.length} notes</span></CardHeader>
          {memory.notes.length === 0 ? <div className="p-4 text-sm text-muted">Hermes has not stored anything yet.</div> : (
            <div className="divide-y divide-border">
              {memory.notes.map((n) => (
                <div key={n.id} className="flex items-start justify-between gap-3 px-4 py-2.5">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted">
                      <Badge variant={n.kind === "human" ? "accent" : n.kind === "outcome" ? "ok" : "default"}>{n.kind === "human" ? "analyst" : n.kind}</Badge>
                      <span>updated {timeAgo(n.updatedAt)}</span>
                    </div>
                    <p className="mt-1 whitespace-pre-wrap text-sm">{n.text}</p>
                  </div>
                  <DeleteNoteButton id={n.id} />
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card>
          <CardHeader><CardTitle>Teach Hermes</CardTitle></CardHeader>
          <CardContent><AddMemoryNoteForm /></CardContent>
        </Card>
      </section>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</dt>
      <dd className="num mt-0.5">{children}</dd>
    </div>
  );
}
