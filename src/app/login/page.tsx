import { redirect } from "next/navigation";
import { Wordmark } from "@/components/soc/brand";
import { env } from "@/lib/env";
import { getSessionState } from "@/lib/auth/session";
import { LoginForm } from "./login-form";

export const metadata = { title: "Sign in" };

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ next?: string; error?: string }> }) {
  const s = await getSessionState();
  if (s.state === "ok") redirect("/");
  const { next, error } = await searchParams;
  const e = env();
  return (
    <main className="grid min-h-screen place-items-center px-4 font-sans">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <Wordmark />
          <p className="text-sm text-muted">One SOC. One interface. Open components underneath.</p>
        </div>
        <LoginForm
          next={next?.startsWith("/") && !next.startsWith("//") ? next : "/"}
          entraEnabled={!!(e.ENTRA_CLIENT_ID && e.ENTRA_CLIENT_SECRET)}
          demo={e.DEMO_MODE === "true"}
          error={error}
        />
        <p className="mt-8 text-center text-[11px] leading-relaxed text-faint">
          Authorised use only. Activity is logged to an immutable audit trail.
          <br />Operated by Yuma IT · Data hosted in Australia.
        </p>
      </div>
    </main>
  );
}
