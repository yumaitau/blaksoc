import { ChevronRight } from "lucide-react";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { auditTrail } from "@/lib/services/admin";
import { fmtDateTime } from "@/lib/utils";
import { VerifyIntegrity } from "./verify";

export const metadata = { title: "Audit trail" };

const ACTOR: Record<string, "default" | "intel" | "warn" | "accent"> = { user: "default", system: "accent", playbook: "intel", ai: "warn" };

export default async function AuditPage({ searchParams }: { searchParams: Promise<{ tenant?: string; action?: string; days?: string }> }) {
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
  const days = [1, 7, 30, 90, 365].includes(Number(sp.days)) ? Number(sp.days) : 30;
  const tenantId = tenants.some((t) => t.id === sp.tenant) ? sp.tenant : undefined;
  const action = sp.action?.trim().slice(0, 60) || undefined;
  const rows = await auditTrail(ctx, { tenantId, action, sinceDays: days, limit: 300 });
  const platformVerify = ctx.isPlatform;

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Govern"
        title="Audit trail"
        description="Each entry's hash covers its content and the previous entry's hash, so any edit or deletion breaks the chain from that point on."
        actions={platformVerify ? <VerifyIntegrity /> : undefined}
      />

      <form className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-surface p-3" method="get">
        <div className="w-56">
          <Label htmlFor="f-tenant">Customer</Label>
          <Select id="f-tenant" name="tenant" defaultValue={tenantId ?? ""}>
            <option value="">{ctx.isPlatform ? "All (including platform)" : "All in scope"}</option>
            {tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </Select>
        </div>
        <div className="w-56">
          <Label htmlFor="f-action">Action starts with</Label>
          <Input id="f-action" name="action" placeholder="e.g. rbac. or response." defaultValue={action ?? ""} />
        </div>
        <div className="w-36">
          <Label htmlFor="f-days">Period</Label>
          <Select id="f-days" name="days" defaultValue={String(days)}>
            {[1, 7, 30, 90, 365].map((d) => <option key={d} value={d}>Last {d} day{d === 1 ? "" : "s"}</option>)}
          </Select>
        </div>
        <Button type="submit" size="sm" variant="secondary">Filter</Button>
      </form>

      <Card>
        <CardHeader>
          <CardTitle>Entries</CardTitle>
          <span className="text-xs text-muted">{rows.length}{rows.length === 300 ? " (latest 300)" : ""}</span>
        </CardHeader>
        {rows.length === 0 ? (
          <div className="p-4"><EmptyState title="No entries">Nothing matches these filters.</EmptyState></div>
        ) : (
          <Table>
            <THead>
              <TR className="hover:bg-transparent"><TH>#</TH><TH>Time</TH><TH>Actor</TH><TH>Customer</TH><TH>Action</TH><TH>Target</TH><TH>Detail</TH><TH>Hash</TH></TR>
            </THead>
            <TBody>
              {rows.map(({ entry: e, actorName, tenantName }) => (
                <TR key={e.id} className="align-top">
                  <TD className="num font-mono text-[11px] text-faint">{e.id}</TD>
                  <TD className="whitespace-nowrap text-xs text-muted">{fmtDateTime(e.at)}</TD>
                  <TD>
                    <div className="flex items-center gap-1.5">
                      <Badge variant={ACTOR[e.actorKind] ?? "default"}>{e.actorKind}</Badge>
                      <span className="truncate text-xs">{actorName ?? (e.actorId ? e.actorId.slice(0, 8) : "—")}</span>
                    </div>
                  </TD>
                  <TD className="text-xs text-muted">{tenantName ?? (e.tenantId ? "—" : "platform")}</TD>
                  <TD className="font-mono text-xs">{e.action}</TD>
                  <TD className="max-w-48 truncate font-mono text-[11px] text-muted" title={e.targetId ?? undefined}>{e.targetType ? `${e.targetType}:${e.targetId ?? ""}` : "—"}</TD>
                  <TD className="max-w-md">
                    {e.detail ? (
                      <details className="group">
                        <summary className="flex cursor-pointer list-none items-center gap-1 text-xs text-muted hover:text-fg">
                          <ChevronRight className="size-3 transition-transform group-open:rotate-90" />JSON
                        </summary>
                        <pre className="mt-1 max-h-64 overflow-auto rounded bg-bg p-2 font-mono text-[11px] leading-snug text-muted">{JSON.stringify(e.detail, null, 2)}</pre>
                      </details>
                    ) : <span className="text-xs text-faint">—</span>}
                  </TD>
                  <TD className="font-mono text-[11px] text-faint" title={e.hash ?? undefined}>{e.hash?.slice(0, 10) ?? "—"}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
