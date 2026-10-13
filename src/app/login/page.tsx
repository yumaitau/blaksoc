import { redirect } from "next/navigation";
import { Wordmark } from "@/components/soc/brand";
import { safeNextPath } from "@/lib/auth/next-path";
import { getSessionState } from "@/lib/auth/session";

export const metadata = { title: "Sign in" };

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ next?: string; error?: string; signedOut?: string }> }) {
  const { next, error, signedOut } = await searchParams;
  const destination = safeNextPath(next);
  const s = await getSessionState();
  if (s.state === "ok") redirect(destination);
  if (s.state === "mfa_enrolment_required") redirect("/account/mfa");
  const start = `/api/auth/cognito?${new URLSearchParams({ next: destination })}`;
  if (!error && !signedOut) redirect(start);
  return (
    <main className="grid min-h-screen place-items-center px-4 font-sans">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <Wordmark />
          <h1 className="text-lg font-semibold">{error ? "Unable to sign in" : "Signed out of blakSOC"}</h1>
        </div>
        <p className="text-sm text-muted">
          {error ? "Amazon Cognito could not complete sign-in. Try again or contact the SOC." : "Your blakSOC session has ended."}
        </p>
        <a className="mt-4 block text-sm text-accent hover:underline" href={start}>
          {error ? "Try again with Amazon Cognito" : "Continue with Amazon Cognito"}
        </a>
        <p className="mt-8 text-center text-[11px] leading-relaxed text-faint">
          Authorised use only. Activity is logged to an immutable audit trail.
          <br />Operated by Yuma IT · Data hosted in Australia.
        </p>
      </div>
    </main>
  );
}
