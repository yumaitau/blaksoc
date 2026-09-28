import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/soc/indicators";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { CATEGORY_LABELS, secretFields } from "@/lib/integrations/form-spec";
import type { ConnectorCategory } from "@/lib/connectors/registry";
import { catalogue, integrationAudit, listIntegrations } from "@/lib/services/integrations";
import { fmtDateTime } from "@/lib/utils";
import { IntegrationForm } from "../integration-form";
import { TestConnection } from "../integration-controls";
import { AuditHistory, ConnectionStatus, KeyValues } from "../parts";
import { LinkTenantForm } from "./link-tenant-form";

export const metadata = { title: "Integration settings" };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function IntegrationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const ctx = await requireAccess();
  const row = (await listIntegrations(ctx)).find((r) => r.id === id);
  if (!row) notFound();
  const def = catalogue().find((c) => c.provider === row.provider);
  const manage = row.tenantId ? can(ctx, "integration:manage", row.tenantId) : ctx.isPlatform && can(ctx, "integration:manage");
  const audit = await integrationAudit(ctx, id);
  const linkable = ctx.isPlatform && !row.tenantId ? ctx.tenants.filter((t) => t.kind === "customer" && can(ctx, "integration:manage", t.id)) : [];
  const health = row.health as { ok?: boolean; latencyMs?: number; detail?: Record<string, unknown> } | null;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={`Integrations · ${CATEGORY_LABELS[row.category as ConnectorCategory] ?? row.category}`}
        title={row.name}
        description={`${def?.name ?? row.provider} · ${row.tenantId ? row.tenantName : "Platform (shared)"} · added ${fmtDateTime(row.createdAt)}`}
        actions={<Link href="/integrations" className="text-sm text-accent hover:underline">← Integrations</Link>}
      />

      <div className="grid gap-5 xl:grid-cols-[1fr_22rem]">
        <div className="space-y-5">
          <Card>
            <CardHeader><CardTitle>Settings</CardTitle>{manage ? <TestConnection id={row.id} /> : null}</CardHeader>
            <CardContent>
              {manage ? (
                <IntegrationForm mode="edit" id={row.id} provider={row.provider} name={row.name} enabled={row.enabled} hasSecret={row.hasSecret} configJson={JSON.stringify(row.config, null, 2)} secretFields={secretFields(row.provider)} />
              ) : (
                <div className="space-y-2">
                  <KeyValues data={row.config} />
                  <p className="text-sm text-muted">You can view this integration but not change it.</p>
                </div>
              )}
            </CardContent>
          </Card>

          {!row.tenantId ? (
            <Card>
              <CardHeader><CardTitle>Customers served</CardTitle><span className="text-xs text-muted">Shared integration: each customer&apos;s data is selected by agent group.</span></CardHeader>
              <CardContent className="space-y-4">
                {row.links.length ? (
                  <ul className="divide-y divide-border rounded-md border border-border">
                    {row.links.map((l) => (
                      <li key={l.tenantId} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                        <span>{l.tenantName}</span>
                        <span className="font-mono text-xs text-muted">{l.selector.agentGroups?.length ? l.selector.agentGroups.join(", ") : "all agents"}</span>
                      </li>
                    ))}
                  </ul>
                ) : <p className="text-sm text-faint">Not linked to any customer yet.</p>}
                {linkable.length ? <LinkTenantForm id={row.id} tenants={linkable.map((t) => ({ id: t.id, name: t.name }))} links={row.links.map((l) => ({ tenantId: l.tenantId, agentGroups: l.selector.agentGroups ?? [] }))} /> : null}
              </CardContent>
            </Card>
          ) : null}
        </div>

        <aside className="space-y-5">
          <Card>
            <CardHeader><CardTitle>Connection</CardTitle><ConnectionStatus status={row.status} enabled={row.enabled} /></CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div><div className="text-[11px] uppercase tracking-wider text-faint">Last successful sync</div>{fmtDateTime(row.lastSuccessAt)}</div>
              <div>
                <div className="text-[11px] uppercase tracking-wider text-faint">Last error</div>
                {row.lastError ? <div className="text-danger break-words">{row.lastError}<div className="text-xs text-muted">{fmtDateTime(row.lastErrorAt)}</div></div> : <span className="text-faint">None</span>}
              </div>
              <div><div className="mb-0.5 text-[11px] uppercase tracking-wider text-faint">Health</div>{health ? <KeyValues data={{ ok: health.ok, latencyMs: health.latencyMs, ...(health.detail ?? {}) }} /> : <span className="text-xs text-faint">No health check yet</span>}</div>
              <div className="text-xs">{row.hasSecret ? <span className="text-ok">Secret stored (encrypted, write-only)</span> : <span className="text-faint">No secret stored</span>}</div>
              {row.permissions.length ? (
                <div>
                  <div className="mb-0.5 text-[11px] uppercase tracking-wider text-faint">Required remote permissions</div>
                  <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted">{row.permissions.map((p) => <li key={p}>{p}</li>)}</ul>
                </div>
              ) : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Audit history</CardTitle></CardHeader>
            <CardContent className="max-h-96 overflow-auto"><AuditHistory rows={audit} /></CardContent>
          </Card>
        </aside>
      </div>
    </div>
  );
}
