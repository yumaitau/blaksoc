"use client";
import Link from "next/link";
import { Button } from "@/components/ui/button";

export type BoundaryError = Error & { digest?: string };

/**
 * Fallback for error boundaries. Production server errors reach the browser as a generic message
 * plus a digest that matches the server log line, so the digest is the reference support asks for.
 */
export function ErrorPanel({ error, retry, home = "/" }: { error: BoundaryError; retry: () => void; home?: string }) {
  const denied = error.name === "AccessDenied" || /\bforbidden\b|not permitted/i.test(error.message ?? "");
  return (
    <div role="alert" className="mx-auto mt-16 max-w-md rounded-lg border border-border bg-surface p-6 text-center">
      <h2 className="font-semibold">{denied ? "You don't have access to this" : "This page couldn't load"}</h2>
      {denied ? (
        <p className="mt-1 text-sm text-muted">Your role doesn&apos;t include this area. Ask a blakSOC administrator if you need it.</p>
      ) : (
        <>
          <p className="mt-1 text-sm text-muted">Usually this is temporary. Try again; if it keeps happening, contact support with the reference below.</p>
          <p className="mt-3 text-xs text-muted">
            Reference <code className="select-all font-mono text-fg">{error.digest ?? "none (the error happened in your browser)"}</code>
          </p>
        </>
      )}
      <div className="mt-4 flex justify-center gap-2">
        {!denied ? <Button variant="secondary" onClick={() => retry()}>Try again</Button> : null}
        <Button variant="ghost" asChild><Link href={home}>Go to the start page</Link></Button>
      </div>
    </div>
  );
}
