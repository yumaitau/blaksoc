"use client";
import { useState, useTransition } from "react";
import { toast } from "sonner";
import type { ActionResult } from "@/lib/actions";

/** Shown when the action never answered: the request failed in transit or the server crashed before withAccess. */
const UNREACHABLE = "Could not reach blakSOC. Check your connection and try again.";

export type RunOptions<T> = {
  /** Toast on success; a function sees the result and may return nothing to stay quiet. Falls back to the action's own message. */
  success?: string | ((data: T | undefined) => string | null | undefined);
};

/**
 * Runs a server action in a transition. Failures are kept for inline display and raised as an
 * error toast; success raises a toast when `options.success` (or the action's message) says so.
 */
export function useAction() {
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function fail(message: string) {
    setError(message);
    // Failures stay up longer than confirmations: they usually need reading.
    toast.error(message, { duration: 8_000 });
  }

  function run<T>(action: () => Promise<ActionResult<T>>, onSuccess?: (data: T | undefined) => void, options?: RunOptions<T>) {
    setError(null);
    start(async () => {
      let res: ActionResult<T>;
      try {
        res = await action();
      } catch {
        return fail(UNREACHABLE);
      }
      if (!res.ok) return fail(res.error);
      const message = typeof options?.success === "function" ? options.success(res.data) : (options?.success ?? res.message);
      if (message) toast.success(message);
      onSuccess?.(res.data);
    });
  }

  // setError stays inline only: it is for client-side checks shown next to the form.
  return { pending, error, setError, run };
}

export function ActionError({ error }: { error: string | null }) {
  return error ? <p role="alert" className="text-sm text-danger">{error}</p> : null;
}
