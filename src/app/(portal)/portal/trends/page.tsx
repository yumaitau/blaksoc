import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { TrendSummary } from "@/components/soc/trend-summary";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { tenantTrends } from "@/lib/services/trends";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Trends" };

/** Customer summary for the workspace tenant. Platform comparison lives on /soc/trends. */
export default async function PortalTrendsPage() {
  const ctx = await requireAccess();
  const ws = await currentWorkspace(ctx);
  const tenant =
    (ws.tenant?.kind === "customer" && can(ctx, "alert:read", ws.tenant.id) ? ws.tenant : null) ??
    ctx.tenants.find((row) => row.kind === "customer" && can(ctx, "alert:read", row.id));
  if (!tenant) {
    return (
      <div>
        <PageHeader title="Trends" />
        <EmptyState title="No organisation to show">Your account is not linked to a customer organisation yet.</EmptyState>
      </div>
    );
  }
  const data = await tenantTrends(ctx, tenant.id);
  return (
    <TrendSummary
      data={data}
      eyebrow={tenant.name}
      title="Trends"
      description="Event volume, top detections, noisy assets, time to open, time to close, and agent health for the last 90 days."
    />
  );
}
