import { Plus } from "lucide-react";
import Link from "next/link";
import { EmptyState, PageHeader, StatusBadge } from "@/components/soc/indicators";
import { conditionText, EVENT_LABELS, isDestructive } from "@/components/soar/flow";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { requireAccess } from "@/lib/auth/session";
import { stepCatalogue } from "@/lib/soar/engine";
import { canWritePlaybook, listPlaybooks, playbookOwners } from "@/lib/services/playbooks";
import { timeAgo } from "@/lib/utils";
import { PlaybookToggle } from "./playbook-toggle";

export const metadata = { title: "Playbooks" };

export default async function PlaybooksPage() {
  const ctx = await requireAccess();
  const [books, catalogue] = [await listPlaybooks(ctx), stepCatalogue()];
  const canCreate = playbookOwners(ctx).length > 0;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect & respond"
        title="Playbooks"
        description="Automated response workflows. Enrichment and notification run automatically; containment always waits for a human approver unless a platform administrator enabled auto-containment for that customer."
        actions={
          <>
            <Button asChild variant="secondary" size="sm"><Link href="/soar/runs">Run history</Link></Button>
            {canCreate ? <Button asChild size="sm"><Link href="/soar/playbooks/new"><Plus />New playbook</Link></Button> : null}
          </>
        }
      />
      <Card>
        {books.length === 0 ? (
          <div className="p-4"><EmptyState title="No playbooks">Create one to automate triage and response.</EmptyState></div>
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>Name</TH>
                <TH>Scope</TH>
                <TH>Trigger</TH>
                <TH className="text-right">Steps</TH>
                <TH className="text-right">Destructive</TH>
                <TH>Version</TH>
                <TH>Last run</TH>
                <TH>Enabled</TH>
              </TR>
            </THead>
            <TBody>
              {books.map((p) => {
                const destructive = p.steps.filter((s) => isDestructive(s.action, catalogue)).length;
                const conds = p.trigger.conditions.map(conditionText).join(" and ");
                return (
                  <TR key={p.id}>
                    <TD className="max-w-80">
                      <Link href={`/soar/playbooks/${p.id}`} className="font-medium hover:text-accent hover:underline">{p.name}</Link>
                      {p.description ? <div className="truncate text-xs text-muted" title={p.description}>{p.description}</div> : null}
                    </TD>
                    <TD>{p.tenantId ? <span className="text-sm">{p.tenantName}</span> : <Badge variant="accent">Global</Badge>}</TD>
                    <TD className="max-w-72">
                      <div className="text-sm">{EVENT_LABELS[p.trigger.event] ?? p.trigger.event}</div>
                      <div className="truncate font-mono text-[11px] text-muted" title={conds}>{conds || "no conditions"}</div>
                    </TD>
                    <TD className="num text-right">{p.steps.length}</TD>
                    <TD className="text-right">{destructive ? <Badge variant="warn">{destructive} gated</Badge> : <span className="text-faint">0</span>}</TD>
                    <TD className="num text-muted">v{p.version}</TD>
                    <TD>{p.lastRunStatus ? <span className="inline-flex items-center gap-2"><StatusBadge status={p.lastRunStatus} /><span className="text-xs text-muted">{timeAgo(p.lastRunAt)}</span></span> : <span className="text-xs text-faint">Never</span>}</TD>
                    <TD><PlaybookToggle id={p.id} name={p.name} enabled={p.enabled} disabled={!canWritePlaybook(ctx, p.tenantId)} /></TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
