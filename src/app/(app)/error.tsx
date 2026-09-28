"use client";
import { Button } from "@/components/ui/button";

export default function AppError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const denied = error.message?.includes("forbidden") || error.name === "AccessDenied";
  return (
    <div className="mx-auto mt-16 max-w-md rounded-lg border border-border bg-surface p-6 text-center">
      <h2 className="font-semibold">{denied ? "You don't have access to this" : "Something went wrong"}</h2>
      <p className="mt-1 text-sm text-muted">{denied ? "Your role doesn't include this area. Ask a blakSOC administrator if you need it." : `Reference ${error.digest ?? "n/a"}. The error has been logged.`}</p>
      {!denied ? <Button className="mt-4" variant="secondary" onClick={reset}>Try again</Button> : null}
    </div>
  );
}
