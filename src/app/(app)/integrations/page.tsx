import { KeyRound, Plus } from "lucide-react";
import Link from "next/link";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { can, tenantsWith } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { CATEGORY_LABELS, CATEGORY_ORDER } from "@/lib/integrations/form-spec";
import { catalogue, integrationAudit, listIntegrations } from "@/lib/services/integrations";
import { fmtDateTime, timeAgo } from "@/lib/utils";
import { IntegrationToggle, TestConnection } from "./integration-controls";
import { AuditHistory, ConnectionStatus, KeyValues, type IntegrationRow } from "./parts";

export const metadata = { title: "Integrations" };

export default async function IntegrationsPage() {
  const ctx = await requireAccess();
  const rows = await listIntegrations(ctx);
  const audits = new Map(await Promise.all(rows.map(async (r) => [r.id, await integrationAudit(ctx, r.id)] as const)));
  const canManage = (tenantId: string | null) => (tenantId ? can(ctx, "integration:manage", tenantId) : ctx.isPlatform && can(ctx, "integration:manage"));
  const canAdd = (ctx.isPlatform && can(ctx, "integration:manage")) || tenantsWith(ctx, "integration:manage").length > 0;
  const cat = catalogue();
  const connectedProviders = new Set(rows.map((r) => r.provider));

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Govern"
        title="Integrations"
        description="Connections to the systems blakSOC reads from and acts on. Secrets are encrypted at rest and write-only: they can be rotated here but never displayed."
      />

      <section className="space-y-5" aria-labelledby="connected-h">
        <h2 id="connected-h" className="text-sm font-semibold">Connected <span className="num ml-1 text-faint">{rows.length}</span></h2>
        {rows.length === 0 ? <EmptyState title="No integrations connected">Add one from the catalogue below.</EmptyState> : null}
        {CATEGORY_ORDER.map((c) => {
          const inCat = rows.filter((r) => r.category === c);
          if (!inCat.length) return null;
          return (
            <div key={c} className="space-y-2">
              <h3 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-faint">{CATEGORY_LABELS[c]}</h3>
              <div className="grid gap-3 xl:grid-cols-2">
                {inCat.map((r) => <IntegrationCard key={r.id} row={r} audit={audits.get(r.id) ?? []} manage={canManage(r.tenantId)} providerName={cat.find((x) => x.provider === r.provider)?.name ?? r.provider} />)}
              </div>
            </div>
          );
        })}
      </section>

      <section className="space-y-3" aria-labelledby="catalogue-h">
        <div>
          <h2 id="catalogue-h" className="text-sm font-semibold">Connector catalogue</h2>
          <p className="text-xs text-muted">Available connectors can be added now. Planned connectors are on the roadmap and cannot yet be configured.</p>
        </div>
        {CATEGORY_ORDER.map((c) => {
          const inCat = cat.filter((x) => x.category === c);
          if (!inCat.length) return null;
          return (
            <div key={c} className="space-y-2">
              <h3 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-faint">{CATEGORY_LABELS[c]}</h3>
              <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                {inCat.map((d) => (
                  <div key={d.provider} className="flex flex-col rounded-lg border border-border bg-surface px-3 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm font-medium">{d.name}</span>
                      {d.status === "available" ? (connectedProviders.has(d.provider) ? <Badge variant="ok">Connected</Badge> : <Badge variant="accent">Available</Badge>) : <Badge variant="outline">Planned</Badge>}
                    </div>
                    <p className="mt-1 line-clamp-2 flex-1 text-xs text-muted" title={d.description}>{d.description}</p>
                    <div className="mt-2 flex flex-wrap items-center gap-1">
                      {d.capabilities.map((cap) => <span key={cap} className="rounded border border-border px-1 font-mono text-[10.5px] text-muted">{cap}</span>)}
                      {d.status === "available" && canAdd ? (
                        <Button asChild size="sm" variant="secondary" className="ml-auto h-6 px-2"><Link href={`/integrations/new?provider=${d.provider}`} aria-label={`Add ${d.name}`}><Plus />Add</Link></Button>
                      ) : null}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </section>
    </div>
  );
}

function IntegrationCard({ row: r, audit, manage, providerName }: { row: IntegrationRow; audit: Awaited<ReturnType<typeof integrationAudit>>; manage: boolean; providerName: string }) {
  const health = r.health as { ok?: boolean; latencyMs?: number; detail?: Record<string, unknown>; error?: string } | null;
  return (
    <Card className="flex flex-col">
      <CardHeader>
        <div className="min-w-0">
          <CardTitle className="truncate"><Link href={`/integrations/${r.id}`} className="hover:text-accent hover:underline">{r.name}</Link></CardTitle>
          <div className="mt-0.5 text-xs text-muted">{providerName} · {r.tenantId ? r.tenantName : "Platform (shared)"}</div>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <ConnectionStatus status={r.status} enabled={r.enabled} />
          <IntegrationToggle id={r.id} name={r.name} enabled={r.enabled} disabled={!manage} />
        </div>
      </CardHeader>
      <CardContent className="grid flex-1 gap-4 text-sm sm:grid-cols-2">
        <div className="space-y-2">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-faint">Last successful sync</div>
            <div title={fmtDateTime(r.lastSuccessAt)}>{r.lastSuccessAt ? timeAgo(r.lastSuccessAt) : <span className="text-faint">Never</span>}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-faint">Last error</div>
            {r.lastError ? <div className="text-danger"><span className="line-clamp-2 break-words" title={r.lastError}>{r.lastError}</span><span className="text-xs text-muted">{timeAgo(r.lastErrorAt)}</span></div> : <div className="text-faint">None</div>}
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-faint">Health</div>
            {health ? <KeyValues data={{ ok: health.ok, latencyMs: health.latencyMs, ...(health.detail ?? {}) }} /> : <span className="text-xs text-faint">No health check yet</span>}
          </div>
          <div className="flex items-center gap-1.5 text-xs">
            <KeyRound className="size-3.5 text-faint" aria-hidden />
            {r.hasSecret ? <span className="text-ok">Secret stored (encrypted)</span> : <span className="text-faint">No secret stored</span>}
          </div>
        </div>
        <div className="space-y-2">
          <div>
            <div className="mb-0.5 text-[11px] uppercase tracking-wider text-faint">Configuration</div>
            <KeyValues data={r.config} />
          </div>
          {r.permissions.length ? (
            <div>
              <div className="mb-0.5 text-[11px] uppercase tracking-wider text-faint">Required remote permissions</div>
              <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted">{r.permissions.map((p) => <li key={p}>{p}</li>)}</ul>
            </div>
          ) : null}
          {!r.tenantId ? (
            <div>
              <div className="mb-0.5 text-[11px] uppercase tracking-wider text-faint">Customers served</div>
              {r.links.length ? (
                <ul className="space-y-0.5 text-xs">
                  {r.links.map((l) => <li key={l.tenantId}>{l.tenantName}{l.selector.agentGroups?.length ? <span className="font-mono text-muted"> · groups: {l.selector.agentGroups.join(", ")}</span> : null}</li>)}
                </ul>
              ) : <span className="text-xs text-faint">Not linked to any customer</span>}
            </div>
          ) : null}
        </div>
      </CardContent>
      <div className="flex flex-wrap items-center gap-3 border-t border-border px-4 py-2.5">
        {manage ? <TestConnection id={r.id} /> : null}
        {manage ? <Link href={`/integrations/${r.id}`} className="text-xs text-accent hover:underline">Edit settings →</Link> : null}
        <details className="basis-full">
          <summary className="cursor-pointer text-xs text-muted hover:text-fg">Audit history ({audit.length})</summary>
          <div className="mt-2 max-h-60 overflow-auto"><AuditHistory rows={audit} /></div>
        </details>
      </div>
    </Card>
  );
}
