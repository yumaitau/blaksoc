import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Card, CardContent } from "@/components/ui/card";
import { requireAccess } from "@/lib/auth/session";
import { aud } from "@/lib/billing/invoice";
import { fmtDateTime } from "@/lib/utils";
import { listPartnerEscalations, partnerCommercialReport, partnerHome } from "@/lib/services/partner";

export const metadata = { title: "Customers" };

const inputCls = "mt-1 w-full min-h-11 rounded-md border border-border bg-transparent px-3 text-base";

export default async function PartnerPage() {
  const ctx = await requireAccess();
  const partnerId = partnerHome(ctx);
  const partner = partnerId ? ctx.tenants.find((tenant) => tenant.id === partnerId) : undefined;
  if (!partnerId || !partner) {
    return (
      <div>
        <PageHeader title="Customers" />
        <EmptyState title="IT provider account needed">This page lists customers who agreed an IT provider can work in their tenancy.</EmptyState>
      </div>
    );
  }
  const [rows, notes] = await Promise.all([
    partnerCommercialReport(ctx, partnerId),
    listPartnerEscalations(ctx, partnerId),
  ]);
  const customers = ctx.tenants.filter((tenant) => tenant.kind === "customer" && tenant.parentId === partnerId);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={partner.cobrand ?? partner.name}
        title="Your customers"
        description="Counts are this month. The share figure is an input for a later invoice. It does not move any money. blakSOC stays named beside your organisation."
      />
      <Card>
        <CardContent className="space-y-3 p-4">
          <h2 className="text-sm font-semibold">Name shown with blakSOC</h2>
          <form action="/portal/partner/save" method="post" className="space-y-3">
            <input type="hidden" name="intent" value="brand" />
            <label className="block text-sm">
              Brand name
              <input className={inputCls} name="brandName" required maxLength={80} defaultValue={partner.brandName ?? partner.name} />
            </label>
            <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">Save name</button>
          </form>
        </CardContent>
      </Card>
      {rows.length === 0 ? <EmptyState title="No consented customers">Finish setup for a customer and record their agreement. Until then this list stays empty.</EmptyState> : (
        <div className="space-y-3">
          {rows.map((row) => (
            <Card key={row.id}>
              <CardContent className="grid gap-3 p-4 sm:grid-cols-2">
                <div>
                  <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Customer</div>
                  <div className="text-sm">{row.name}</div>
                </div>
                <div>
                  <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Plan</div>
                  <div className="text-sm">{row.plan.tier}{row.plan.nonprofit ? " · community" : ""}</div>
                </div>
                <div>
                  <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Protected users</div>
                  <div className="text-sm">{row.usage.protectedUsers}</div>
                </div>
                <div>
                  <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Devices</div>
                  <div className="text-sm">{row.usage.endpoints}</div>
                </div>
                <div>
                  <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Ex GST ({row.priceSource})</div>
                  <div className="text-sm">AUD {aud(row.exGstCents)}</div>
                </div>
                <div>
                  <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Share {row.shareBps / 100}%</div>
                  <div className="text-sm">AUD {aud(row.shareExGstCents)}</div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      <Card>
        <CardContent className="space-y-3 p-4">
          <h2 className="text-sm font-semibold">Ask the Yuma IT SOC</h2>
          <p className="text-sm text-muted">This records the note for the SOC. It does not open a ticket with anyone outside blakSOC.</p>
          {customers.length === 0 ? null : (
            <form action="/portal/partner/save" method="post" className="space-y-3">
              <input type="hidden" name="intent" value="escalate" />
              <label className="block text-sm">
                Customer
                <select className={inputCls} name="tenantId" required>
                  {customers.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
                </select>
              </label>
              <label className="block text-sm">
                What should the SOC look at?
                <textarea className={inputCls} name="note" required maxLength={2000} rows={3} />
              </label>
              <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">Send to the SOC</button>
            </form>
          )}
          {notes.length ? (
            <ul className="space-y-2 text-sm">
              {notes.map((note) => (
                <li key={note.id}>
                  <span className="text-muted">{fmtDateTime(note.createdAt)} · {note.customer}</span>
                  <div>{note.note}</div>
                </li>
              ))}
            </ul>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
