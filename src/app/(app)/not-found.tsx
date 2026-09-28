import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto mt-16 max-w-md rounded-lg border border-border bg-surface p-6 text-center">
      <h2 className="font-semibold">Not found</h2>
      <p className="mt-1 text-sm text-muted">It doesn&apos;t exist, or it belongs to a tenant outside your scope.</p>
      <Link href="/" className="mt-4 inline-block text-sm text-accent hover:underline">Back to blakSOC</Link>
    </div>
  );
}
