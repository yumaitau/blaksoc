import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { can, tenantsWith } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { CATEGORY_LABELS, exampleConfig, secretFields } from "@/lib/integrations/form-spec";
import { catalogue } from "@/lib/services/integrations";
import { IntegrationForm } from "../integration-form";

export const metadata = { title: "Add integration" };

export default async function NewIntegrationPage({ searchParams }: { searchParams: Promise<{ provider?: string }> }) {
  const ctx = await requireAccess();
  const { provider } = await searchParams;
  const def = catalogue().find((c) => c.provider === provider && c.status === "available");
  if (!def) notFound();
  const manageable = tenantsWith(ctx, "integration:manage");
  const owners = [
    ...(ctx.isPlatform && can(ctx, "integration:manage") && provider !== "syslog" ? [{ id: null, name: "Platform (shared)" }] : []),
    ...ctx.tenants.filter((t) => manageable.includes(t.id)).map((t) => ({ id: t.id as string | null, name: t.name })),
  ];
  if (!owners.length) redirect("/integrations");

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Integrations"
        title={`Add ${def.name}`}
        description={def.description}
        actions={<Link href="/integrations" className="text-sm text-accent hover:underline">← Integrations</Link>}
      />
      <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
        <Card><CardContent><IntegrationForm mode="create" provider={def.provider} name={def.name} owners={owners} configJson={JSON.stringify(exampleConfig(def.provider), null, 2)} secretFields={secretFields(def.provider)} /></CardContent></Card>
        <aside className="space-y-3 text-sm">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-faint">Category</div>
            <div>{CATEGORY_LABELS[def.category]}</div>
          </div>
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-faint">Capabilities</div>
            <div className="flex flex-wrap gap-1">{def.capabilities.map((c) => <Badge key={c} variant="outline">{c}</Badge>)}</div>
          </div>
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-faint">Required remote permissions</div>
            {def.remotePermissions.length ? <ul className="list-disc space-y-1 pl-4 text-xs text-muted">{def.remotePermissions.map((p) => <li key={p}>{p}</li>)}</ul> : <p className="text-xs text-faint">None</p>}
          </div>
          <p className="text-xs text-muted">The integration is tested on demand from its settings page. Secrets are encrypted with AES-256-GCM and are never shown again after saving.</p>
        </aside>
      </div>
    </div>
  );
}
