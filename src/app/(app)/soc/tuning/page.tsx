import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { listNoiseRules, recentAnnotations } from "@/lib/services/tuning";
import { fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { RuleControls } from "./controls";

export const metadata = { title: "Noise tuning" };

const STATUS_BADGE: Record<string, "warn" | "ok" | "default" | "danger"> = { proposed: "warn", active: "ok", expired: "default", rejected: "danger" };

/**
 * Noise rules: what is kept out of the queue, why, by whom, until when, and how often it matched. Every
 * change here is audited (noise_rule.*); expired rules stop matching on their own.
 */
export default async function TuningPage() {
  const ctx = await requireAccess();
  if (!ctx.isPlatform || !can(ctx, "alert:tune")) redirect("/soc");
  const ws = await currentWorkspace(ctx);
  const [rules, notes] = await Promise.all([listNoiseRules(ctx, ws.tenantIds), recentAnnotations(ctx, ws.tenantIds)]);
  const proposed = rules.filter((r) => r.status === "proposed").length;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect & respond"
        title="Noise tuning"
        description="Rules that move known noise to the passive lane. Alerts stay stored and searchable; nothing is closed. Every rule expires (30 days by default, 180 at most)."
        actions={<Link href="/soc/hermes" className="text-xs text-accent hover:underline">Hermes actions and switch →</Link>}
      />

      <Card>
        <CardHeader>
          <CardTitle>Noise rules</CardTitle>
          <span className="text-xs text-muted">{proposed ? `${proposed} proposal${proposed === 1 ? "" : "s"} awaiting review · ` : ""}Create one from an alert with “Mark as noise…”</span>
        </CardHeader>
        {rules.length === 0 ? (
          <div className="p-4"><EmptyState title="No noise rules yet">Open a noisy alert and choose “Mark as noise…”.</EmptyState></div>
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>Status</TH>
                <TH>Customer</TH>
                <TH>Matches</TH>
                <TH>Reason</TH>
                <TH>By</TH>
                <TH className="text-right">Hits</TH>
                <TH>Expires</TH>
                <TH>Actions</TH>
              </TR>
            </THead>
            <TBody>
              {rules.map(({ rule: r, status, tenantName, assetName, createdByName, approvedByName }) => (
                <TR key={r.id}>
                  <TD><Badge variant={STATUS_BADGE[status] ?? "default"}>{status}</Badge></TD>
                  <TD className="max-w-36 truncate text-xs text-muted">{tenantName}</TD>
                  <TD className="max-w-64 text-xs">
                    <div className="truncate"><span className="text-muted">{r.source}</span> rule <span className="font-mono">{r.ruleId}</span></div>
                    <div className="truncate text-[11px] text-faint">
                      {r.assetId ? <>on <Link href={`/assets/${r.assetId}`} className="hover:text-accent">{assetName ?? r.hostname ?? "one host"}</Link></> : r.hostname ? `on ${r.hostname}` : "every host"}
                      {r.titlePattern ? <> · titles like <span className="font-mono">{r.titlePattern}</span></> : null}
                      {r.maxSeverity ? ` · up to ${r.maxSeverity}` : ""}
                    </div>
                  </TD>
                  <TD className="max-w-72 text-xs">
                    <div className="line-clamp-2" title={r.reason}>{r.reason}</div>
                    {r.evidence ? <div className="truncate text-[11px] text-faint" title={r.evidence}>{r.evidence}</div> : null}
                  </TD>
                  <TD className="max-w-40 text-xs">
                    <div className="truncate">{r.createdByKind === "service" ? `${createdByName ?? "API client"} (automation)` : (createdByName ?? "unknown")}</div>
                    {approvedByName && r.createdByKind === "service" ? <div className="truncate text-[11px] text-faint">approved by {approvedByName}</div> : null}
                  </TD>
                  <TD className="num text-right text-xs">
                    {r.hitCount}
                    {r.lastHitAt ? <div className="text-[11px] text-faint" title={fmtDateTime(r.lastHitAt)}>{timeAgo(r.lastHitAt)}</div> : null}
                  </TD>
                  <TD className="whitespace-nowrap text-xs text-muted" title={fmtDateTime(r.expiresAt)}>{timeAgo(r.expiresAt)}</TD>
                  <TD><RuleControls id={r.id} status={status} /></TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>

      <Card>
        <CardHeader><CardTitle>Hermes (AI) notes</CardTitle><span className="text-xs text-muted">Interpretation, not evidence. Shown on matching alerts too.</span></CardHeader>
        {notes.length === 0 ? (
          <div className="p-4 text-sm text-muted">No notes yet.</div>
        ) : (
          <div className="divide-y divide-border">
            {notes.map((n) => (
              <div key={n.id} className="px-4 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted">
                  <span>{n.tenantName} · {n.source} rule <span className="font-mono">{n.ruleId}</span></span>
                  <span>{n.confidence} confidence · {timeAgo(n.createdAt)}</span>
                </div>
                <p className="mt-1 whitespace-pre-wrap text-sm">{n.text}</p>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
