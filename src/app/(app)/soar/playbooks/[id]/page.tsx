import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/soc/indicators";
import { RunsTable } from "@/components/soar/runs-table";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { can, tenantsWith } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { listAlerts } from "@/lib/services/alerts";
import { canWritePlaybook, getPlaybook, listRuns } from "@/lib/services/playbooks";
import { stepCatalogue } from "@/lib/soar/engine";
import { fmtDateTime } from "@/lib/utils";
import { PlaybookEditor } from "../playbook-editor";
import { PlaybookToggle } from "../playbook-toggle";
import { RunManually } from "./run-manually";

export const metadata = { title: "Playbook" };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function PlaybookPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const ctx = await requireAccess();
  const pb = await getPlaybook(ctx, id);
  if (!pb) notFound();
  const canEdit = canWritePlaybook(ctx, pb.tenantId);
  const runTenants = tenantsWith(ctx, "playbook:run", pb.tenantId ? [pb.tenantId] : undefined);
  const [runs, recent] = await Promise.all([
    listRuns(ctx, { playbookId: id, limit: 25 }),
    runTenants.length && can(ctx, "alert:read") ? listAlerts(ctx, { tenantIds: runTenants, sort: "newest", limit: 40 }).then((r) => r.rows) : Promise.resolve([]),
  ]);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Playbooks"
        title={pb.name}
        description={pb.description ?? undefined}
        actions={
          <>
            <Link href="/soar/playbooks" className="text-sm text-accent hover:underline">← All playbooks</Link>
            <span className="inline-flex items-center gap-2 text-sm text-muted">Enabled <PlaybookToggle id={pb.id} name={pb.name} enabled={pb.enabled} disabled={!canEdit} /></span>
          </>
        }
      />
      <div className="-mt-3 flex flex-wrap items-center gap-2 text-xs text-muted">
        {pb.tenantId ? <Badge variant="outline">{pb.tenantName}</Badge> : <Badge variant="accent">Global template</Badge>}
        <span>Version {pb.version}</span>·<span>updated {fmtDateTime(pb.updatedAt)}</span>
      </div>

      <PlaybookEditor
        canEdit={canEdit}
        catalogue={stepCatalogue()}
        owners={[{ id: pb.tenantId, name: pb.tenantName ?? "Global (all customers)" }]}
        initial={{ id: pb.id, tenantId: pb.tenantId, name: pb.name, description: pb.description, trigger: pb.trigger, steps: pb.steps }}
      />

      {runTenants.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Run manually</CardTitle>
            <span className="text-xs text-muted">Skips trigger conditions. Approval gates still apply.</span>
          </CardHeader>
          <CardContent>
            <RunManually playbookId={pb.id} alerts={recent.map((a) => ({ id: a.id, label: `[${a.riskScore}] ${a.title} · ${a.tenantName}${a.assetName ? ` · ${a.assetName}` : ""}` }))} />
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Run history</CardTitle>
          <Link href="/soar/runs" className="text-xs text-accent hover:underline">All runs →</Link>
        </CardHeader>
        <RunsTable runs={runs} showPlaybook={false} />
      </Card>
    </div>
  );
}
