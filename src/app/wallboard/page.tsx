import { Wallboard } from "@/components/wallboard/wallboard";
import { assertCan } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "SOC wallboard", referrer: "no-referrer" as const, robots: { index: false, follow: false } };
export const dynamic = "force-dynamic";

export default async function WallboardPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const params = await searchParams;
  const query = new URLSearchParams();
  // A supplied credential never falls back to a signed-in session, even if malformed.
  if (params.token !== undefined) {
    query.set("token", typeof params.token === "string" ? params.token : "");
  } else {
    const ctx = await requireAccess();
    assertCan(ctx, "dashboard:read");
    if (params.tenantIds !== undefined) {
      const scopes = typeof params.tenantIds === "string" ? [params.tenantIds] : params.tenantIds;
      for (const scope of scopes) query.append("tenantIds", scope);
    } else {
      const ws = await currentWorkspace(ctx);
      const ids = ws.tenantIds.filter((id) => ctx.tenants.some((tenant) => tenant.id === id && tenant.kind === "customer"));
      if (ids.length) query.set("tenantIds", ids.join(","));
    }
  }
  const endpoint = `/api/wallboard?${query}`;
  return <Wallboard key={endpoint} endpoint={endpoint} />;
}
