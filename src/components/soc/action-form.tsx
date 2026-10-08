"use client";
import type { ActionResult } from "@/lib/actions";
import { cn } from "@/lib/utils";
import { ActionError, useAction } from "./use-action";

/**
 * A form for server-rendered pages whose action takes FormData and returns an ActionResult.
 * Submits through useAction, so it toasts and shows errors like every client form; the fields
 * are disabled while the action runs. `reset` clears the inputs after a success.
 */
export function ActionForm({
  action,
  success,
  reset,
  className,
  children,
}: {
  action: (formData: FormData) => Promise<ActionResult>;
  success: string;
  reset?: boolean;
  className?: string;
  children: React.ReactNode;
}) {
  const { pending, error, run } = useAction();
  return (
    <form
      aria-busy={pending}
      onSubmit={(e) => {
        e.preventDefault();
        const form = e.currentTarget;
        const data = new FormData(form);
        run(() => action(data), () => reset && form.reset(), { success });
      }}
    >
      <fieldset disabled={pending} className={cn("min-w-0", className)}>{children}</fieldset>
      <div className="mt-2 empty:hidden"><ActionError error={error} /></div>
    </form>
  );
}
