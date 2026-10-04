import type { ResponseActionState } from "@/lib/providers/types";

/** How long an endpoint may take to report an asynchronous action before blakSOC gives up. */
export const PENDING_TIMEOUT_MS = 15 * 60_000;

/** Stored in response_actions.result while an asynchronous provider action is in flight. */
export type PendingResult = {
  message: string;
  providerRef: string;
  pending: true;
  assetExternalId: string;
  dispatchedAt: string;
  providerState?: ResponseActionState["state"];
};

export function isPendingResult(v: unknown): v is PendingResult {
  const r = v as Partial<PendingResult> | null;
  return !!r && r.pending === true && typeof r.providerRef === "string" && typeof r.assetExternalId === "string" && typeof r.dispatchedAt === "string";
}

export type PendingDecision = { final: false; state: ResponseActionState | null } | { final: true; ok: boolean; message: string };

/**
 * Settles a pending action from the provider's latest answer. `state` is null when the provider
 * could not be asked (error); that keeps waiting until the timeout, which always fails the action.
 */
export function decidePending(state: ResponseActionState | null, dispatchedAt: Date, now: Date, timeoutMs = PENDING_TIMEOUT_MS): PendingDecision {
  if (state?.state === "succeeded") return { final: true, ok: true, message: state.message };
  if (state?.state === "failed") return { final: true, ok: false, message: state.message };
  if (now.getTime() - dispatchedAt.getTime() >= timeoutMs) {
    const last = state ? ` (last state: ${state.state})` : "";
    return { final: true, ok: false, message: `timed out waiting for endpoint after ${Math.round(timeoutMs / 60_000)} min${last}` };
  }
  return { final: false, state };
}
