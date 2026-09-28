import Link from "next/link";
import { EmptyState, StatusBadge } from "@/components/soc/indicators";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import type { listRuns } from "@/lib/services/playbooks";
import { fmtDateTime, timeAgo } from "@/lib/utils";

type Run = Awaited<ReturnType<typeof listRuns>>[number];

export function RunsTable({ runs, showPlaybook = true }: { runs: Run[]; showPlaybook?: boolean }) {
  if (!runs.length) return <div className="p-4"><EmptyState title="No runs yet">Runs appear here when a trigger matches or an analyst runs the playbook manually.</EmptyState></div>;
  return (
    <Table>
      <THead>
        <TR className="hover:bg-transparent">
          <TH>Run</TH>
          {showPlaybook ? <TH>Playbook</TH> : null}
          <TH>Customer</TH>
          <TH>Trigger</TH>
          <TH>Status</TH>
          <TH>Started</TH>
          <TH>Finished</TH>
          <TH>Linked</TH>
        </TR>
      </THead>
      <TBody>
        {runs.map((r) => (
          <TR key={r.id}>
            <TD><Link href={`/soar/runs/${r.id}`} className="font-mono text-xs text-accent hover:underline">{r.id.slice(0, 8)}</Link></TD>
            {showPlaybook ? (
              <TD>
                <Link href={`/soar/playbooks/${r.playbookId}`} className="hover:underline">{r.playbookName}</Link>
                <span className="ml-1.5 text-[11px] text-faint">v{r.playbookVersion}</span>
              </TD>
            ) : null}
            <TD className="text-muted">{r.tenantName}</TD>
            <TD className="font-mono text-xs text-muted">{r.event ?? "—"}</TD>
            <TD>
              <StatusBadge status={r.status} />
              {r.error ? <div className="mt-0.5 max-w-56 truncate text-[11px] text-danger" title={r.error}>{r.error}</div> : null}
            </TD>
            <TD className="text-xs text-muted" title={fmtDateTime(r.startedAt)}>{timeAgo(r.startedAt)}</TD>
            <TD className="text-xs text-muted">{r.finishedAt ? fmtDateTime(r.finishedAt) : "—"}</TD>
            <TD className="space-x-2 text-xs whitespace-nowrap">
              {r.alertId ? <Link href={`/soc/alerts/${r.alertId}`} className="text-accent hover:underline">Alert</Link> : null}
              {r.incidentId ? <Link href={`/soc/incidents/${r.incidentId}`} className="text-accent hover:underline">Incident</Link> : null}
              {!r.alertId && !r.incidentId ? <span className="text-faint">—</span> : null}
            </TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}
