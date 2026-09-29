import { redirect } from "next/navigation";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { COPY } from "@/lib/onboarding/copy";

export const viewport = { themeColor: "#0d0f12", width: "device-width", initialScale: 1 };

const REGISTER_SW = `if("serviceWorker"in navigator){navigator.serviceWorker.register("/sw.js")}`;

export default async function PortalLayout({ children }: { children: React.ReactNode }) {
  const ctx = await requireAccess();
  if (!ctx.grants.length || !ctx.tenantIds.length) redirect("/access-pending");
  return (
    <div className="portal-root mx-auto min-h-screen max-w-3xl px-4 py-4">
      <a className="skip-link" href="#portal-main">Skip to content</a>
      <header className="mb-4 flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3">
        <a className="inline-flex min-h-11 items-center text-base font-semibold" href="/portal">blakSOC</a>
        <nav aria-label="Portal" className="flex flex-wrap items-center gap-1">
          <a className="inline-flex min-h-11 items-center px-2 underline" href="/portal">Overview</a>
          <a className="inline-flex min-h-11 items-center px-2 underline" href="/portal/usage">Usage</a>
          {can(ctx, "report:generate") ? <a className="inline-flex min-h-11 items-center px-2 underline" href="/portal/essential-eight">Essential Eight</a> : null}
          {ctx.isPlatform && can(ctx, "tenant:manage") ? <a className="inline-flex min-h-11 items-center px-2 underline" href="/onboarding">{COPY.nav}</a> : null}
          {ctx.isPlatform ? <a className="inline-flex min-h-11 items-center px-2 underline" href="/soc">SOC</a> : null}
          <form action="/portal/leave" method="post">
            <button className="inline-flex min-h-11 items-center px-2 underline" type="submit">Sign out</button>
          </form>
        </nav>
      </header>
      <main id="portal-main">{children}</main>
      <p className="mt-8 text-sm text-muted">You can install this portal on your phone. After you open it once, the last incident status stays on the phone when you have no coverage.</p>
      <script dangerouslySetInnerHTML={{ __html: REGISTER_SW }} />
    </div>
  );
}
