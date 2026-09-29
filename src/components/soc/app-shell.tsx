import {
  Bug, Building2, FileText, FolderKanban, Grid3x3, LayoutDashboard, Plug, Radar, ScanSearch, ScrollText, Server, Settings, ShieldCheck, Siren, Sparkles, Workflow,
} from "lucide-react";
import { can, type AccessContext } from "@/lib/auth/access";
import { Wordmark } from "./brand";
import { LiveUpdates } from "./live-updates";
import { NAV } from "./nav";
import { NavLink } from "./nav-link";
import { SignOutButton } from "./sign-out";
import { WorkspaceSwitcher } from "./workspace-switcher";

const ICONS = { Bug, Building2, FileText, FolderKanban, Grid3x3, LayoutDashboard, Plug, Radar, ScanSearch, ScrollText, Server, Settings, ShieldCheck, Siren, Sparkles, Workflow } as const;

export function AppShell({ ctx, workspace, children }: { ctx: AccessContext; workspace: string; children: React.ReactNode }) {
  const groups = NAV.map((g) => ({ ...g, items: g.items.filter((i) => can(ctx, i.perm) && (!i.platformOnly || ctx.isPlatform) && !(i.href === "/portal" && ctx.isPlatform)) })).filter((g) => g.items.length);
  const customers = ctx.tenants.filter((t) => t.kind === "customer");
  const roleNames = [...new Set(ctx.grants.map((g) => g.roleKey.replaceAll("_", " ")))].join(", ");

  return (
    <div className="flex min-h-screen font-sans">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-border bg-surface md:flex">
        <div className="flex h-14 items-center border-b border-border px-4">
          <Wordmark />
        </div>
        <nav className="flex-1 overflow-y-auto px-2 py-3">
          {groups.map((g) => (
            <div key={g.label} className="mb-4">
              <div className="px-2 pb-1 text-[10.5px] font-semibold uppercase tracking-[0.12em] text-faint">{g.label}</div>
              {g.items.map((i) => {
                const Icon = ICONS[i.icon as keyof typeof ICONS];
                return (
                  <NavLink key={i.href} href={i.href}>
                    <Icon className="size-4" />
                    {i.label}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="border-t border-border p-3">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="truncate text-sm font-medium">{ctx.principal.name}</div>
              <div className="truncate text-[11px] capitalize text-faint">{roleNames || "no role"}</div>
            </div>
            <SignOutButton compact />
          </div>
          {ctx.principal.isBreakGlass ? <div className="mt-2 rounded bg-danger/15 px-2 py-1 text-[11px] font-medium text-danger">Break-glass session</div> : null}
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 min-w-0 items-center justify-between gap-2 border-b border-border bg-bg/85 px-4 backdrop-blur md:gap-4 md:px-6">
          <div className="flex min-w-0 flex-1 items-center gap-2 md:flex-none md:gap-3">
            <div className="shrink-0 md:hidden">
              <Wordmark />
            </div>
            {customers.length > 1 || ctx.isPlatform ? <WorkspaceSwitcher tenants={customers} current={workspace} /> : <div className="truncate text-sm font-medium">{customers[0]?.name}</div>}
          </div>
          <LiveUpdates />
        </header>
        <main className="min-w-0 flex-1 px-4 py-6 md:px-6">{children}</main>
      </div>
    </div>
  );
}
