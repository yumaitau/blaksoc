import { ChevronRight, Download } from "lucide-react";
import Link from "next/link";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { describeAuditEntry, auditTargetLabel, redactAuditDetail } from "@/lib/audit/describe";
import { AUDIT_ACTOR_KINDS, AUDIT_PERIODS, auditQuery, parseAuditFilters, type AuditFilters } from "@/lib/audit/filters";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { auditTrail } from "@/lib/services/admin";
import { fmtDateTime } from "@/lib/utils";
import { VerifyIntegrity } from "./verify";

export const metadata = { title: "Audit trail" };

const PAGE_SIZE = 300;
const ACTOR: Record<string, "default" | "intel" | "warn" | "accent"> = { user: "default", system: "accent", playbook: "intel", ai: "warn", service: "accent" };
const ACTOR_LABEL: Record<string, string> = { user: "Person", system: "System", playbook: "Playbook", ai: "AI analyst", service: "Service identity" };

const href = (f: AuditFilters, opts: { before?: number } = {}) => {
  const qs = auditQuery(f, opts);
  return qs ? `/admin/audit?${qs}` : "/admin/audit";
};

export default async function AuditPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const tenants = ctx.tenants.filter((t) => can(ctx, "audit:read", t.id));
  if (!can(ctx, "audit:read")) {
    return (
      <>
        <PageHeader eyebrow="Govern" title="Audit trail" />
        <EmptyState title="No access to the audit trail">Reading the audit trail needs the audit permission.</EmptyState>
      </>
    );
  }
  const f = parseAuditFilters(sp, tenants.map((t) => t.id));
  const { rows, nextBefore, names } = await auditTrail(ctx, f, PAGE_SIZE);
  const platformVerify = ctx.isPlatform;
  const exportQs = auditQuery(f);
  const filtered = exportQs !== "";
  const readable = new Set(tenants.map((t) => t.id));

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Govern"
        title="Audit trail"
        description="Who did what, and when. Each entry's hash covers its content and the previous entry's hash, so any edit or deletion breaks the chain from that point on."
        actions={
          <div className="flex flex-wrap items-center gap-3">
            <Button asChild size="sm" variant="secondary">
              <a href={`/admin/audit/export${exportQs ? `?${exportQs}` : ""}`} download>
                <Download />Download CSV
              </a>
            </Button>
            {platformVerify ? <VerifyIntegrity /> : null}
          </div>
        }
      />

      <form className="grid grid-cols-2 items-end gap-3 rounded-lg border border-border bg-surface p-3 md:grid-cols-4 xl:grid-cols-6" method="get">
        <div>
          <Label htmlFor="f-tenant">Customer</Label>
          <Select id="f-tenant" name="tenant" defaultValue={f.tenantId ?? ""}>
            <option value="">{ctx.isPlatform ? "All (including platform)" : "All in scope"}</option>
            {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-actor">Actor</Label>
          <Input id="f-actor" name="actor" maxLength={120} placeholder="Name, email or id" defaultValue={f.actor ?? ""} />
        </div>
        <div>
          <Label htmlFor="f-kind">Actor kind</Label>
          <Select id="f-kind" name="actorKind" defaultValue={f.actorKind ?? ""}>
            <option value="">Any</option>
            {AUDIT_ACTOR_KINDS.map((k) => <option key={k} value={k}>{ACTOR_LABEL[k]}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-action">Action starts with</Label>
          <Input id="f-action" name="action" maxLength={60} placeholder="e.g. rbac. or response." defaultValue={f.action ?? ""} />
        </div>
        <div>
          <Label htmlFor="f-q">Search</Label>
          <Input id="f-q" name="q" maxLength={100} placeholder="Action or target" defaultValue={f.q ?? ""} />
        </div>
        <div>
          <Label htmlFor="f-ttype">Target type</Label>
          <Input id="f-ttype" name="targetType" maxLength={40} placeholder="e.g. alert, user" defaultValue={f.targetType ?? ""} />
        </div>
        <div>
          <Label htmlFor="f-tid">Target ID</Label>
          <Input id="f-tid" name="targetId" maxLength={200} defaultValue={f.targetId ?? ""} />
        </div>
        <div>
          <Label htmlFor="f-days">Period</Label>
          <Select id="f-days" name="days" defaultValue={String(f.sinceDays)}>
            {AUDIT_PERIODS.map((d) => <option key={d} value={d}>Last {d} day{d === 1 ? "" : "s"}</option>)}
          </Select>
        </div>
        <div>
          <Label htmlFor="f-from">From</Label>
          <Input id="f-from" name="from" type="date" defaultValue={f.from ?? ""} />
        </div>
        <div>
          <Label htmlFor="f-to">To</Label>
          <Input id="f-to" name="to" type="date" defaultValue={f.to ?? ""} />
        </div>
        <div className="col-span-2 flex items-center gap-3">
          <Button type="submit" size="sm" variant="secondary">Filter</Button>
          {filtered ? <Link href="/admin/audit" className="text-xs text-accent hover:underline">Clear filters</Link> : null}
          <span className="text-[11px] text-faint">From/To (Sydney time) replace the period.</span>
        </div>
      </form>

      <Card>
        <CardHeader>
          <CardTitle>Entries</CardTitle>
          <span className="text-xs text-muted">
            {rows.length.toLocaleString("en-AU")} on this page{nextBefore ? " · older entries follow" : ""}
          </span>
        </CardHeader>
        {rows.length === 0 ? (
          <div className="p-4"><EmptyState title="No entries">Nothing matches these filters.</EmptyState></div>
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent"><TH>Time</TH><TH>Actor</TH><TH>Customer</TH><TH>What happened</TH><TH>Target</TH><TH>IP</TH><TH>Details</TH></TR>
            </THead>
            <TBody>
              {rows.map(({ entry: e, actorName, actorEmail, tenantName }) => {
                const { summary, targetHref } = describeAuditEntry(e, names);
                const target = auditTargetLabel(e.targetType, e.targetId);
                return (
                  <TR key={e.id} className="align-top">
                    <TD className="whitespace-nowrap text-xs text-muted">{fmtDateTime(e.at)}</TD>
                    <TD>
                      <div className="flex min-w-0 flex-col items-start gap-1">
                        {e.actorId ? (
                          <Link href={href({ ...f, before: undefined, actor: e.actorId })} title={actorEmail ?? e.actorId} className="max-w-44 truncate text-xs hover:text-accent hover:underline">
                            {actorName ?? e.actorId.slice(0, 8)}
                          </Link>
                        ) : (
                          <span className="text-xs text-muted">{e.actorKind === "system" ? "blakSOC" : "—"}</span>
                        )}
                        <Badge variant={ACTOR[e.actorKind] ?? "default"}>{ACTOR_LABEL[e.actorKind] ?? e.actorKind}</Badge>
                      </div>
                    </TD>
                    <TD className="text-xs text-muted">
                      {e.tenantId && readable.has(e.tenantId) ? (
                        <Link href={href({ ...f, before: undefined, tenantId: e.tenantId })} className="hover:text-accent hover:underline">{tenantName ?? "—"}</Link>
                      ) : (tenantName ?? (e.tenantId ? "—" : "platform"))}
                    </TD>
                    <TD className="max-w-md">
                      <div className="text-sm">{summary}</div>
                      {summary !== e.action ? <div className="font-mono text-[11px] text-faint">{e.action}</div> : null}
                    </TD>
                    <TD className="max-w-48 text-xs" title={e.targetId ?? undefined}>
                      {targetHref ? (
                        <Link href={targetHref} className="text-accent hover:underline">{target}</Link>
                      ) : (
                        <span className="text-muted">{target}</span>
                      )}
                    </TD>
                    <TD className="whitespace-nowrap font-mono text-[11px] text-muted">{e.ip ?? "—"}</TD>
                    <TD className="max-w-md">
                      <details className="group">
                        <summary className="flex cursor-pointer list-none items-center gap-1 text-xs text-muted hover:text-fg">
                          <ChevronRight className="size-3 transition-transform group-open:rotate-90" />Show
                        </summary>
                        <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-[11px]">
                          <dt className="text-faint">Entry</dt><dd className="font-mono">#{e.id}</dd>
                          <dt className="text-faint">Hash</dt><dd className="break-all font-mono text-faint">{e.hash ?? "—"}</dd>
                          {e.targetId ? <><dt className="text-faint">Target ID</dt><dd className="break-all font-mono">{e.targetId}</dd></> : null}
                        </dl>
                        {e.detail ? (
                          <pre className="mt-1 max-h-64 overflow-auto rounded bg-bg p-2 font-mono text-[11px] leading-snug text-muted">{JSON.stringify(redactAuditDetail(e.detail), null, 2)}</pre>
                        ) : null}
                      </details>
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
        {f.before || nextBefore ? (
          <nav aria-label="Pages" className="flex items-center justify-between border-t border-border px-4 py-2 text-xs">
            {f.before ? <Link href={href(f)} className="text-accent hover:underline">← Newest</Link> : <span />}
            {nextBefore ? <Link href={href(f, { before: nextBefore })} className="text-accent hover:underline">Older →</Link> : null}
          </nav>
        ) : null}
      </Card>
    </div>
  );
}
