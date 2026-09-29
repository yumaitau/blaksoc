import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Card, CardContent } from "@/components/ui/card";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { TIER_LABEL } from "@/lib/billing/catalogue";
import { customerUsage } from "@/lib/services/billing";
import { fmtDateTime } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Usage" };

function gb(bytes: number): string {
  const n = bytes / 1e9;
  if (n === 0) return "0";
  if (n < 0.001) return n.toFixed(6);
  return n.toLocaleString("en-AU", { minimumFractionDigits: 3, maximumFractionDigits: 3 });
}

/** Customer view: plan name, pilot end, and this month's counts. No rate card. */
export default async function PortalUsagePage() {
  const ctx = await requireAccess();
  const ws = await currentWorkspace(ctx);
  const tenant =
    (ws.tenant?.kind === "customer" && can(ctx, "portal:read", ws.tenant.id) ? ws.tenant : null) ??
    ctx.tenants.find((t) => t.kind === "customer" && can(ctx, "portal:read", t.id));
  if (!tenant) {
    return (
      <div>
        <PageHeader title="Usage" />
        <EmptyState title="No organisation to show">Your account is not linked to a customer organisation yet.</EmptyState>
      </div>
    );
  }
  const { plan, usage } = await customerUsage(ctx, tenant.id);

  const lines = [
    ["Plan", TIER_LABEL[plan.tier]],
    ["Pilot ends", plan.pilotEndsAt ? fmtDateTime(plan.pilotEndsAt) : "None"],
    ["Protected users", String(usage.protectedUsers)],
    ["Devices", String(usage.endpoints)],
    ["Domains", String(usage.domains)],
    ["Data received", `${gb(usage.bytesIngested)} GB`],
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={tenant.name}
        title="Usage"
        description="Your plan and what we counted this month. User, device and domain counts are the latest snapshot. Data received is the month total."
      />
      <Card>
        <CardContent className="grid gap-3 p-4 sm:grid-cols-2">
          {lines.map(([label, value]) => (
            <div key={label}>
              <div className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</div>
              <div className="text-sm">{value}</div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
