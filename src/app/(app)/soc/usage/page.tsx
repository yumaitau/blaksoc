import { redirect } from "next/navigation";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Card } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { TIER_LABEL } from "@/lib/billing/catalogue";
import { requireAccess } from "@/lib/auth/session";
import { usageDashboard, type UsageRow } from "@/lib/services/billing";
import { fmtDateTime } from "@/lib/utils";

export const metadata = { title: "Usage" };

function gb(bytes: number): string {
  const n = bytes / 1e9;
  if (n === 0) return "0";
  if (n < 0.001) return n.toFixed(6);
  return n.toLocaleString("en-AU", { minimumFractionDigits: 3, maximumFractionDigits: 3 });
}

function pilot(row: UsageRow) {
  return row.plan.pilotEndsAt ? fmtDateTime(row.plan.pilotEndsAt) : "None";
}

/** Yuma IT view: every customer, the plan flags, this month's counts, and quote downloads. */
export default async function SocUsagePage() {
  const ctx = await requireAccess();
  if (!ctx.isPlatform) redirect("/portal/usage");
  const rows = await usageDashboard(ctx);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Govern"
        title="Usage"
        description="Counts for each customer this month. User, device and domain figures are the latest snapshot. Data received is the month total. Prices on a quote are an indicative rate card. The Indigenous advisory group has not signed these prices off."
      />
      <Card>
        {rows.length === 0 ? (
          <div className="p-4">
            <EmptyState title="No customers">No customer tenants are in your scope.</EmptyState>
          </div>
        ) : (
          <>
          <div className="space-y-3 p-3 md:hidden">
            {rows.map((row) => (
              <div key={row.id} className="rounded-md border border-border p-3 text-sm">
                <div className="font-medium">{row.name}</div>
                <div className="mt-1 text-muted">{TIER_LABEL[row.plan.tier]} · Nonprofit {row.plan.nonprofit ? "yes" : "no"} · Pilot {pilot(row)}</div>
                <div className="mt-2">{row.usage.protectedUsers} users · {row.usage.endpoints} devices · {row.usage.domains} domains · {gb(row.usage.bytesIngested)} GB</div>
                <div className="mt-2">
                  <a className="underline" href={`/api/billing/${row.id}/quote?format=csv`}>CSV</a>
                  {" · "}
                  <a className="underline" href={`/api/billing/${row.id}/quote?format=pdf`}>PDF</a>
                </div>
              </div>
            ))}
          </div>
          <div className="hidden md:block">
          <Table>
            <THead>
              <tr className="border-b border-border">
                <TH>Customer</TH>
                <TH>Plan</TH>
                <TH>Nonprofit</TH>
                <TH>Pilot ends</TH>
                <TH className="text-right">Users</TH>
                <TH className="text-right">Devices</TH>
                <TH className="text-right">Domains</TH>
                <TH className="text-right">GB</TH>
                <TH>Quote</TH>
              </tr>
            </THead>
            <TBody>
              {rows.map((row) => (
                <TR key={row.id}>
                  <TD>{row.name}</TD>
                  <TD>{TIER_LABEL[row.plan.tier]}</TD>
                  <TD>{row.plan.nonprofit ? "Yes" : "No"}</TD>
                  <TD>{pilot(row)}</TD>
                  <TD className="text-right">{row.usage.protectedUsers}</TD>
                  <TD className="text-right">{row.usage.endpoints}</TD>
                  <TD className="text-right">{row.usage.domains}</TD>
                  <TD className="text-right">{gb(row.usage.bytesIngested)}</TD>
                  <TD>
                    <a className="underline" href={`/api/billing/${row.id}/quote?format=csv`}>CSV</a>
                    {" · "}
                    <a className="underline" href={`/api/billing/${row.id}/quote?format=pdf`}>PDF</a>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
          </div>
          </>
        )}
      </Card>
    </div>
  );
}
