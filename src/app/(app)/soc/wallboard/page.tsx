import Link from "next/link";
import { Monitor } from "lucide-react";
import { PageHeader } from "@/components/soc/indicators";
import { assertCan } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { canManageWallboardLinks, listWallboardLinks, wallboardSnapshot } from "@/lib/services/wallboard";
import { currentWorkspace } from "@/lib/workspace";
import { DisplayLinks } from "./display-links";

export const metadata = { title: "TV wallboard" };

export default async function WallboardSettingsPage() {
  const ctx = await requireAccess();
  assertCan(ctx, "dashboard:read");
  const ws = await currentWorkspace(ctx);
  const ids = ws.tenantIds.filter((id) => ctx.tenants.some((tenant) => tenant.id === id && tenant.kind === "customer"));
  const manage = canManageWallboardLinks(ctx);
  const [snapshot, links] = await Promise.all([wallboardSnapshot(ctx, ids), manage ? listWallboardLinks(ctx) : Promise.resolve([])]);
  return <div className="space-y-6">
    <PageHeader title="TV wallboard" description="An at-a-glance overview for the office: queue, incidents, customer posture and endpoint reporting." />
    <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg bg-surface p-5">
      <div className="flex items-center gap-3"><Monitor className="size-6 text-accent" aria-hidden="true" /><div><h2 className="font-medium">Open the office display</h2><p className="text-sm text-muted">Uses your current workspace. Refreshes every 30 seconds, with full-screen controls.</p></div></div>
      <Link href="/wallboard" target="_blank" rel="noopener noreferrer" className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">Open wallboard</Link>
    </div>
    {manage ? <DisplayLinks key={snapshot.customers.map(({ id }) => id).sort().join(",")} customers={snapshot.customers.map(({ id, name }) => ({ id, name }))} initialLinks={links} initialNow={Date.parse(snapshot.generatedAt)} /> : <p className="text-sm text-muted">SOC managers and platform administrators can generate a signed display link for a TV that does not sign in.</p>}
  </div>;
}
