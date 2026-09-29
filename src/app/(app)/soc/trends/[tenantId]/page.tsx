import { notFound, redirect } from "next/navigation";
import { TrendSummary } from "@/components/soc/trend-summary";
import { AccessDenied } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { tenantTrends } from "@/lib/services/trends";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const metadata = { title: "Operational trends" };

export default async function TenantTrendsPage({ params }: { params: Promise<{ tenantId: string }> }) {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal/trends");
  const { tenantId } = await params;
  if (!UUID.test(tenantId)) notFound();
  const tenant = ctx.tenants.find((row) => row.id === tenantId);
  let data;
  try {
    data = await tenantTrends(ctx, tenantId);
  } catch (err) {
    if (err instanceof AccessDenied) notFound();
    throw err;
  }
  return (
    <TrendSummary
      data={data}
      eyebrow={tenant?.name ?? "Customer"}
      title="Operational trends"
      description="Event volume, top detections, noisy assets, time to open, time to close, and agent health."
    />
  );
}
