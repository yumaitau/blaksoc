import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, PageHeader, RiskScore } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { listAssets } from "@/lib/services/assets";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { AgentStatus, ASSET_KINDS, Criticality, Exposure } from "./asset-bits";

export const metadata = { title: "Assets" };

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.trim() || undefined;

/** Unified inventory: one row per deduplicated asset across every integration. */
export default async function AssetsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const ctx = await requireAccess();
  if (!can(ctx, "asset:read")) redirect("/portal");
  const sp = await searchParams;
  const ws = await currentWorkspace(ctx);
  const tenantParam = one(sp.tenant);
  const tenantIds = tenantParam && ctx.tenantIds.includes(tenantParam) ? [tenantParam] : ws.tenantIds;
  const kind = ASSET_KINDS.find((k) => k === one(sp.kind));
  const q = one(sp.q);
  const minCrit = Number(one(sp.minCriticality)) || undefined;

  const rows = await listAssets(ctx, { tenantIds, kind, q, minCriticality: minCrit });
  const multiTenant = tenantIds.length > 1;
  const scope = tenantIds.length === 1 ? (ctx.tenants.find((t) => t.id === tenantIds[0])?.name ?? "this customer") : "all customers";

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Investigate"
        title="Assets"
        description={`Unified inventory for ${scope}, deduplicated across every integration. Sorted by risk, then criticality.`}
      />

      <form className="flex flex-wrap items-end gap-3" role="search" aria-label="Filter assets">
        {tenantParam ? <input type="hidden" name="tenant" value={tenantParam} /> : null}
        <div className="w-64">
          <Label htmlFor="q">Search</Label>
          <Input id="q" name="q" defaultValue={q} placeholder="Name, hostname or IP" />
        </div>
        <div className="w-44">
          <Label htmlFor="kind">Kind</Label>
          <Select id="kind" name="kind" defaultValue={kind ?? ""}>
            <option value="">All kinds</option>
            {ASSET_KINDS.map((k) => <option key={k} value={k}>{k.replaceAll("_", " ")}</option>)}
          </Select>
        </div>
        <div className="w-40">
          <Label htmlFor="minCriticality">Min criticality</Label>
          <Select id="minCriticality" name="minCriticality" defaultValue={minCrit ? String(minCrit) : ""}>
            <option value="">Any</option>
            {[2, 3, 4, 5].map((c) => <option key={c} value={c}>{c}+</option>)}
          </Select>
        </div>
        <Button type="submit" variant="secondary">Apply</Button>
        {q || kind || minCrit || tenantParam ? <Link href="/assets" className="pb-2 text-sm text-muted hover:text-fg">Clear</Link> : null}
        <span className="ml-auto pb-2 text-xs text-muted">{rows.length} asset{rows.length === 1 ? "" : "s"}{rows.length >= 500 ? " (first 500)" : ""}</span>
      </form>

      <Card>
        {rows.length === 0 ? (
          <div className="p-4"><EmptyState title="No assets match">Adjust the filters, or check that integrations are syncing inventory.</EmptyState></div>
        ) : (
          <Table>
            <THead>
              <tr className="border-b border-border">
                <TH>Name</TH>
                <TH>Kind</TH>
                {multiTenant ? <TH>Customer</TH> : null}
                <TH>Criticality</TH>
                <TH>Exposure</TH>
                <TH>Agent</TH>
                <TH>Risk</TH>
                <TH className="text-right">Open alerts</TH>
                <TH className="text-right">Open vulns</TH>
                <TH className="text-right" title="Integrations this asset was deduplicated from">Sources</TH>
                <TH>Last seen</TH>
              </tr>
            </THead>
            <TBody>
              {rows.map((a) => (
                <TR key={a.id}>
                  <TD className="max-w-72">
                    <Link href={`/assets/${a.id}`} className="block truncate font-medium hover:text-accent">{a.name}</Link>
                    <div className="truncate text-[11px] text-faint">{[a.hostname !== a.name ? a.hostname : null, a.ips[0], a.os].filter(Boolean).join(" · ") || "—"}</div>
                  </TD>
                  <TD className="text-xs text-muted">{a.kind.replaceAll("_", " ")}</TD>
                  {multiTenant ? <TD className="whitespace-nowrap text-xs">{a.tenantName}</TD> : null}
                  <TD><Criticality value={a.criticality} /></TD>
                  <TD><Exposure value={a.exposure} /></TD>
                  <TD><AgentStatus status={a.agentStatus} /></TD>
                  <TD><RiskScore score={a.riskScore} /></TD>
                  <TD className={cn("num text-right", a.openAlerts ? "font-semibold" : "text-faint")}>{a.openAlerts}</TD>
                  <TD className={cn("num text-right", a.openVulns ? "font-semibold" : "text-faint")}>{a.openVulns}</TD>
                  <TD className="text-right">{a.sources > 1 ? <Badge variant="intel" title="Merged from multiple integrations">{a.sources} merged</Badge> : <span className="num text-faint">{a.sources}</span>}</TD>
                  <TD className="whitespace-nowrap text-xs text-muted" title={fmtDateTime(a.lastSeen)}>{timeAgo(a.lastSeen)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
