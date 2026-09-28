import Link from "next/link";
import { redirect } from "next/navigation";
import { AttackChips, EmptyState, PageHeader, SeverityBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { listRules } from "@/lib/services/detections";
import { fmtDateTime } from "@/lib/utils";
import { RuleEnabledToggle } from "./rule-controls";

export const metadata = { title: "Detections" };

export default async function DetectionsPage({ searchParams }: { searchParams: Promise<{ scope?: string; enabled?: string; technique?: string }> }) {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal");
  const sp = await searchParams;
  const technique = sp.technique?.trim().toUpperCase() ?? "";
  const tenantName = new Map(ctx.tenants.map((t) => [t.id, t.name]));

  // scope: "" = all, "global" = platform rules, otherwise a tenant id.
  const all = await listRules(ctx, { tenantId: sp.scope === "global" ? null : sp.scope && ctx.tenantIds.includes(sp.scope) ? sp.scope : undefined });
  const rows = all.filter(({ rule }) => {
    if (sp.enabled === "yes" && !rule.enabled) return false;
    if (sp.enabled === "no" && rule.enabled) return false;
    if (technique && !rule.attackTechniques.some((t) => t === technique || t.startsWith(`${technique}.`))) return false;
    return true;
  });
  const canWrite = can(ctx, "detection:write");
  const customers = ctx.tenants.filter((t) => t.kind === "customer");
  const filtered = !!(sp.scope || sp.enabled || technique);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect"
        title="Detection rules"
        description="Sigma rule repository. Every change is versioned, tested against sample events and deployed per customer as a scheduled Wazuh-indexer query."
        actions={
          <>
            <Button asChild variant="secondary"><Link href="/detections/attack">ATT&CK coverage</Link></Button>
            {canWrite ? <Button asChild><Link href="/detections/new">New rule</Link></Button> : null}
          </>
        }
      />

      <form action="/detections" className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-surface px-4 py-3">
        <div className="w-56">
          <Label htmlFor="f-scope">Scope</Label>
          <Select id="f-scope" name="scope" defaultValue={sp.scope ?? ""}>
            <option value="">All rules</option>
            <option value="global">Global (platform)</option>
            {customers.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </Select>
        </div>
        <div className="w-36">
          <Label htmlFor="f-enabled">State</Label>
          <Select id="f-enabled" name="enabled" defaultValue={sp.enabled ?? ""}>
            <option value="">Any</option>
            <option value="yes">Enabled</option>
            <option value="no">Disabled</option>
          </Select>
        </div>
        <div className="w-40">
          <Label htmlFor="f-technique">ATT&CK technique</Label>
          <Input id="f-technique" name="technique" defaultValue={technique} placeholder="T1059" className="font-mono" />
        </div>
        <Button type="submit" variant="secondary">Filter</Button>
        {filtered ? <Link href="/detections" className="pb-2 text-xs text-accent hover:underline">Clear</Link> : null}
        <span className="ml-auto pb-2 text-xs text-muted">{rows.length} of {all.length} rules</span>
      </form>

      <Card>
        {rows.length === 0 ? (
          <div className="p-4">
            <EmptyState title={filtered ? "No rules match these filters" : "No detection rules yet"}>
              {filtered ? "Clear the filters or widen the technique." : "Create a Sigma rule to start building coverage."}
            </EmptyState>
          </div>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Rule</TH>
                <TH>Scope</TH>
                <TH>Status</TH>
                <TH>Severity</TH>
                <TH className="text-right">Confidence</TH>
                <TH>ATT&CK</TH>
                <TH>Enabled</TH>
                <TH className="text-right">Version</TH>
                <TH className="text-right">Deployments</TH>
                <TH>Updated</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map(({ rule, deployments }) => (
                <TR key={rule.id}>
                  <TD className="max-w-sm">
                    <Link href={`/detections/rules/${rule.id}`} className="block truncate font-medium hover:text-accent hover:underline">{rule.title}</Link>
                    {rule.description ? <div className="truncate text-xs text-muted">{rule.description}</div> : null}
                  </TD>
                  <TD className="text-xs whitespace-nowrap">{rule.tenantId ? <Badge variant="outline">{tenantName.get(rule.tenantId) ?? "Customer"}</Badge> : <Badge variant="accent">Global</Badge>}</TD>
                  <TD><Badge variant={rule.status === "stable" ? "ok" : rule.status === "deprecated" ? "danger" : "default"}>{rule.status}</Badge></TD>
                  <TD><SeverityBadge severity={rule.severity} /></TD>
                  <TD className="num text-right">{rule.confidence}</TD>
                  <TD><AttackChips techniques={rule.attackTechniques} /></TD>
                  <TD><RuleEnabledToggle id={rule.id} title={rule.title} enabled={rule.enabled} canWrite={canWrite} /></TD>
                  <TD className="num text-right text-muted">v{rule.currentVersion}</TD>
                  <TD className="num text-right">{deployments ? deployments : <span className="text-faint">0</span>}</TD>
                  <TD className="text-xs text-muted whitespace-nowrap">{fmtDateTime(rule.updatedAt)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
