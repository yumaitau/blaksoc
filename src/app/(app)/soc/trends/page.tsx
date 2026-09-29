import Link from "next/link";
import { redirect } from "next/navigation";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { requireAccess } from "@/lib/auth/session";
import { customerTrends } from "@/lib/services/trends";

export const metadata = { title: "Customer trends" };

function minutes(value: number | null) {
  if (value == null) return "No closed incidents";
  return `${Math.round(value)} min`;
}

/** Compare customers on the last 90 days. The live queue stays on the SOC dashboard. */
export default async function CustomerTrendsPage() {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal/trends");
  const rows = await customerTrends(ctx);
  const totals = rows.reduce((sum, row) => ({ alerts: sum.alerts + row.alerts, offline: sum.offline + row.offline, seats: sum.seats + row.seats }), { alerts: 0, offline: 0, seats: 0 });

  return (
    <div className="space-y-5">
      <PageHeader eyebrow="Operate" title="Customer trends" description="Alert volume, close time, offline agents, and seats for the last 90 days." />
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-border bg-surface px-3 py-3">
          <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Customers</div>
          <div className="mt-1 text-lg font-semibold">{rows.length}</div>
        </div>
        <div className="rounded-lg border border-border bg-surface px-3 py-3">
          <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Alerts</div>
          <div className="mt-1 text-lg font-semibold">{totals.alerts}</div>
        </div>
        <div className="rounded-lg border border-border bg-surface px-3 py-3">
          <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Agents offline</div>
          <div className="mt-1 text-lg font-semibold">{totals.offline}</div>
        </div>
      </section>
      {rows.length === 0 ? (
        <EmptyState title="No customers">No customer tenants are in your scope.</EmptyState>
      ) : (
        <ul className="grid gap-3">
          {rows.map((row) => (
            <li key={row.id} className="min-w-0 rounded-lg border border-border bg-surface p-3">
              <Link href={`/soc/trends/${row.id}`} className="font-medium hover:text-accent">{row.name}</Link>
              <div className="mt-2 grid grid-cols-2 gap-2 text-sm">
                <div className="text-muted">Alerts <span className="num text-fg">{row.alerts}</span></div>
                <div className="text-muted">Seats <span className="num text-fg">{row.seats}</span></div>
                <div className="text-muted">Offline <span className="num text-fg">{row.offline}</span></div>
                <div className="min-w-0 text-muted">Time to close <span className="text-fg">{minutes(row.mttrMinutes)}</span></div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
