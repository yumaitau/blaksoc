import Link from "next/link";
import { Wordmark } from "@/components/soc/brand";
import { requireAccess } from "@/lib/auth/session";

export const metadata = { title: "Sign-in security" };

export default async function SecurityPage() {
  await requireAccess();
  return (
    <main className="grid min-h-screen place-items-center px-4 font-sans">
      <div className="w-full max-w-md space-y-4 rounded-lg border border-border bg-surface p-6">
        <Wordmark />
        <h1 className="text-lg font-semibold">Sign-in security</h1>
        <p className="text-sm text-muted">
          Amazon Cognito manages your email/password sign-in and authenticator MFA. Use Forgot password on the Cognito sign-in page to reset your password, or contact the SOC for MFA recovery.
        </p>
        <Link className="block text-xs text-faint hover:text-muted" href="/">Back to blakSOC</Link>
      </div>
    </main>
  );
}
