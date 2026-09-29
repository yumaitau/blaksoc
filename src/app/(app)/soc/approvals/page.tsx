import { Bot, UserRound, Workflow } from "lucide-react";
import Link from "next/link";
import { EmptyState, PageHeader, StatusBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { listApprovals } from "@/lib/soar/response";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { Decision } from "./decision";

export const metadata = { title: "Approvals" };

type Row = Awaited<ReturnType<typeof listApprovals>>[number];

export default async function Approvals({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const ctx = await requireAccess();
  const history = (await searchParams).tab === "history";
  const ws = await currentWorkspace(ctx);
  const rows = (await listApprovals(ctx, history ? "ALL" : "PENDING")).filter((r) => ws.tenantIds.includes(r.approval.tenantId));
  const now = new Date().getTime();

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Respond"
        title="Approvals"
        description="Destructive response actions and gated playbook steps wait here for a human decision. AI-requested actions are never auto-approved."
      />

      <nav aria-label="Approval views" className="flex gap-1 border-b border-border">
        {[{ label: "Pending", href: "/soc/approvals", active: !history }, { label: "History", href: "/soc/approvals?tab=history", active: history }].map(({ label, href, active }) => (
          <Link
            key={label}
            href={href}
            aria-current={active ? "page" : undefined}
            className={cn("-mb-px border-b-2 px-3 py-2 text-sm", active ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg")}
          >
            {label}
          </Link>
        ))}
      </nav>

      {rows.length === 0 ? (
        <EmptyState title={history ? "No approval history" : "Nothing awaiting approval"}>
          {history ? "Decisions will appear here once made." : "Destructive actions requested by analysts, playbooks or the AI analyst will appear here."}
        </EmptyState>
      ) : (
        <Card className="divide-y divide-border">
          {rows.map((r) => {
            const expired = r.approval.status === "PENDING" && r.approval.expiresAt && r.approval.expiresAt.getTime() < now;
            const decidable = !history && !expired && can(ctx, "response:approve", r.approval.tenantId);
            return (
              <article key={r.approval.id} className={cn("grid gap-4 px-4 py-3.5 lg:grid-cols-[1fr_22rem]", r.approval.requestedByKind === "ai" && "border-l-2 border-l-intel")}>
                <div className="min-w-0 space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <Requester kind={r.approval.requestedByKind} name={r.requesterName} />
                    {r.approval.destructive ? <Badge variant="danger">Destructive</Badge> : null}
                    <Badge variant="outline">{r.approval.kind === "playbook_step" ? "Playbook step" : r.approval.kind === "dfir_collection" ? "Collection" : "Response action"}</Badge>
                    {history || expired ? <StatusBadge status={expired ? "EXPIRED" : r.approval.status} /> : null}
                  </div>
                  <p className="text-sm font-medium">{r.approval.summary}</p>
                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-muted">
                    <span>{r.tenantName}</span>
                    <span title={fmtDateTime(r.approval.createdAt)}>requested {timeAgo(r.approval.createdAt)}</span>
                    {r.approval.status === "PENDING" && r.approval.expiresAt ? (
                      <span className={expired ? "text-danger" : r.approval.expiresAt.getTime() - now < 3600_000 ? "text-warn" : undefined} title={fmtDateTime(r.approval.expiresAt)}>
                        {expired ? "expired" : "expires"} {timeAgo(r.approval.expiresAt)}
                      </span>
                    ) : null}
                    {r.action?.incidentId ? <Link href={`/soc/incidents/${r.action.incidentId}`} className="text-accent hover:underline">Incident</Link> : null}
                    {r.action?.alertId ? <Link href={`/soc/alerts/${r.action.alertId}`} className="text-accent hover:underline">Alert</Link> : null}
                  </div>
                  {r.approval.decidedAt ? (
                    <div className="text-xs text-muted">
                      {r.approval.status.toLowerCase()} by {r.deciderName ?? "unknown"} · {fmtDateTime(r.approval.decidedAt)}
                      {r.approval.decisionNote ? <span className="block text-faint">&ldquo;{r.approval.decisionNote}&rdquo;</span> : null}
                    </div>
                  ) : null}
                </div>
                {decidable ? (
                  <Decision approvalId={r.approval.id} destructive={r.approval.destructive} />
                ) : !history && !expired ? (
                  <p className="self-center text-xs text-faint">A SOC Manager must decide this request.</p>
                ) : null}
              </article>
            );
          })}
        </Card>
      )}
    </div>
  );
}

/** Makes machine provenance obvious: an approver must know when an AI or playbook, not a person, asked for this. */
function Requester({ kind, name }: { kind: Row["approval"]["requestedByKind"]; name: string | null }) {
  if (kind === "ai") return <Badge variant="intel"><Bot className="size-3" /> Requested by AI analyst{name ? ` (for ${name})` : ""}</Badge>;
  if (kind === "playbook") return <Badge variant="accent"><Workflow className="size-3" /> Requested by playbook</Badge>;
  return <Badge><UserRound className="size-3" /> {name ?? "Analyst"}</Badge>;
}
