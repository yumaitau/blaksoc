/**
 * A tuning request blakSOC refuses on policy: a guardrail, the act switch, a cap, a version conflict.
 * The message is written for people (and for the agent's log); it never carries alert content.
 * Deliberately without `code`, so server actions show the message as written (see action-errors).
 */
export class TuningRefused extends Error {
  constructor(
    message: string,
    readonly status: 400 | 403 | 404 | 409 | 413 | 422 | 429 = 409,
    readonly error: string = status === 404 ? "not_found" : status === 422 ? "refused" : status === 429 ? "rate_limited" : status === 413 ? "too_large" : "conflict",
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "TuningRefused";
  }
}
