import { redirect } from "next/navigation";
import { AppShell } from "@/components/soc/app-shell";
import { requireAccess } from "@/lib/auth/session";
import { currentWorkspace } from "@/lib/workspace";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const ctx = await requireAccess();
  if (!ctx.grants.length || !ctx.tenantIds.length) redirect("/access-pending");
  const ws = await currentWorkspace(ctx);
  return (
    <AppShell ctx={ctx} workspace={ws.tenant?.id ?? "all"}>
      {children}
    </AppShell>
  );
}
