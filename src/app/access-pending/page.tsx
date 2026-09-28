import { Wordmark } from "@/components/soc/brand";
import { SignOutButton } from "@/components/soc/sign-out";

export const metadata = { title: "Access pending" };

export default function AccessPending() {
  return (
    <main className="grid min-h-screen place-items-center px-4">
      <div className="max-w-md space-y-3 rounded-lg border border-border bg-surface p-6">
        <Wordmark />
        <h1 className="text-lg font-semibold">You&apos;re signed in, but have no access yet</h1>
        <p className="text-sm text-muted">Your identity was verified by your organisation, but no blakSOC role has been assigned. Ask your organisation&apos;s blakSOC administrator or the Yuma IT SOC to grant access.</p>
        <SignOutButton />
      </div>
    </main>
  );
}
