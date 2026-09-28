import Link from "next/link";
import { EmptyState, PageHeader, SeverityBadge, StatusBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { requireAccess } from "@/lib/auth/session";
import { listIncidents } from "@/lib/services/incidents";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Incidents" };

type SearchParams = Record<string, string | string[] | undefined>;

export default async function Incidents({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const ws = await currentWorkspace(ctx);
  const showAll = sp.scope === "all";
  const mine = sp.owner === "me";
  const incidents = await listIncidents(ctx, { tenantIds: ws.tenantIds, open: !showAll, owner: mine ? "me" : undefined });
  const now = new Date().getTime();

  const href = (p: { scope?: string; owner?: string }) => {
    const qs = new URLSearchParams(Object.entries(p).filter((e): e is [string, string] => !!e[1])).toString();
    return qs ? `/soc/incidents?${qs}` : "/soc/incidents";
  };
  const chips = [
    { label: "Open", href: href({ owner: mine ? "me" : undefined }), active: !showAll },
    { label: "All", href: href({ scope: "all", owner: mine ? "me" : undefined }), active: showAll },
  ];

  return (
    <div className="space-y-4">
      <PageHeader eyebrow="Respond" title="Incidents" description={`Cases for ${ws.tenant ? ws.tenant.name : "all customers"}, most recently updated first.`} />

      <nav aria-label="Incident filters" className="flex flex-wrap items-center gap-1.5">
        {chips.map((c) => (
          <Link key={c.label} href={c.href} aria-current={c.active ? "page" : undefined} className={cn("rounded-full border px-2.5 py-1 text-xs", c.active ? "border-accent bg-accent-soft text-accent" : "border-border text-muted hover:text-fg")}>
            {c.label}
          </Link>
        ))}
        <span className="mx-1 h-4 w-px bg-border" />
        <Link
          href={href({ scope: showAll ? "all" : undefined, owner: mine ? undefined : "me" })}
          aria-pressed={mine}
          className={cn("rounded-full border px-2.5 py-1 text-xs", mine ? "border-accent bg-accent-soft text-accent" : "border-border text-muted hover:text-fg")}
        >
          Owned by me
        </Link>
      </nav>

      <Card>
        {incidents.length === 0 ? (
          <div className="p-4"><EmptyState title="No incidents">{showAll ? "No incidents in this workspace." : "No open incidents. Escalate alerts from the queue to open one."}</EmptyState></div>
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>Ref</TH>
                <TH>Severity</TH>
                <TH>Title</TH>
                <TH>Customer</TH>
                <TH>Status</TH>
                <TH>Owner</TH>
                <TH className="text-right">Alerts</TH>
                <TH>SLA due</TH>
                <TH>Updated</TH>
              </TR>
            </THead>
            <TBody>
              {incidents.map((i) => {
                const active = !["CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"].includes(i.status);
                const breached = active && i.slaDueAt && i.slaDueAt.getTime() < now;
                return (
                  <TR key={i.id}>
                    <TD className="num whitespace-nowrap font-mono text-xs text-faint">
                      <Link href={`/soc/incidents/${i.id}`} className="hover:text-accent">INC-{i.ref}</Link>
                    </TD>
                    <TD><SeverityBadge severity={i.severity} /></TD>
                    <TD className="max-w-md">
                      <Link href={`/soc/incidents/${i.id}`} className="block truncate font-medium hover:text-accent">{i.title}</Link>
                    </TD>
                    <TD className="max-w-40 truncate text-xs text-muted">{i.tenantName}</TD>
                    <TD><StatusBadge status={i.status} /></TD>
                    <TD className="max-w-36 truncate text-xs">{i.ownerName ?? <span className="text-faint">Unowned</span>}</TD>
                    <TD className="num text-right text-xs">{i.alertCount}</TD>
                    <TD className="whitespace-nowrap text-xs" title={fmtDateTime(i.slaDueAt)}>
                      {breached ? <Badge variant="danger">Breached {timeAgo(i.slaDueAt)}</Badge> : active && i.slaDueAt ? <span className="text-muted">{timeAgo(i.slaDueAt)}</span> : <span className="text-faint">—</span>}
                    </TD>
                    <TD className="whitespace-nowrap text-xs text-muted" title={fmtDateTime(i.updatedAt)}>{timeAgo(i.updatedAt)}</TD>
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
