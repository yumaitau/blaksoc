"use client";
import { useState, useTransition } from "react";
import type { ActionResult } from "@/lib/actions";

/** Runs a server action in a transition and keeps its error for inline display. */
export function useAction() {
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);

  function run<T>(action: () => Promise<ActionResult<T>>, onSuccess?: (data: T | undefined) => void) {
    setError(null);
    start(async () => {
      const res = await action();
      if (res.ok) onSuccess?.(res.data);
      else setError(res.error);
    });
  }

  return { pending, error, setError, run };
}

export function ActionError({ error }: { error: string | null }) {
  return error ? <p role="alert" className="text-sm text-danger">{error}</p> : null;
}
