import Link from "next/link";
import { PageHeader } from "@/components/soc/indicators";
import { RunsTable } from "@/components/soar/runs-table";
import { Card } from "@/components/ui/card";
import { requireAccess } from "@/lib/auth/session";
import { listRuns } from "@/lib/services/playbooks";
import { cn } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Playbook runs" };

const FILTERS = ["all", "RUNNING", "WAITING_APPROVAL", "SUCCEEDED", "FAILED", "CANCELLED"] as const;

export default async function RunsPage({ searchParams }: { searchParams: Promise<{ status?: string }> }) {
  const ctx = await requireAccess();
  const ws = await currentWorkspace(ctx);
  const { status } = await searchParams;
  const runs = await listRuns(ctx, { tenantIds: ws.tenantIds, limit: 200 });
  const shown = status && status !== "all" ? runs.filter((r) => r.status === status) : runs;

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Detect & respond"
        title="Playbook runs"
        description={`Every automated run across ${ws.tenant ? ws.tenant.name : "all customers"}, with its step outcomes and approval gates.`}
        actions={<Link href="/soar/playbooks" className="text-sm text-accent hover:underline">Playbooks →</Link>}
      />
      <nav className="flex flex-wrap gap-1" aria-label="Filter by status">
        {FILTERS.map((f) => {
          const active = (status ?? "all") === f;
          const n = f === "all" ? runs.length : runs.filter((r) => r.status === f).length;
          return (
            <Link key={f} href={f === "all" ? "/soar/runs" : `/soar/runs?status=${f}`} aria-current={active ? "page" : undefined}
              className={cn("rounded-md border px-2.5 py-1 text-xs", active ? "border-accent bg-accent-soft text-accent" : "border-border text-muted hover:text-fg")}>
              {f === "all" ? "All" : f.replaceAll("_", " ").toLowerCase()} <span className="num ml-1 text-faint">{n}</span>
            </Link>
          );
        })}
      </nav>
      <Card><RunsTable runs={shown} /></Card>
    </div>
  );
}
