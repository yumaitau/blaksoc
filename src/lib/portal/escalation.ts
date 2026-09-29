export type Channel = "sms" | "voice" | "email";
export type EscalationSeverity = "critical" | "high" | "medium" | "low";

export type EscalationStep = {
  severity: EscalationSeverity;
  channel: Channel;
  contacts: string[];
  minIntervalMs: number;
  maxAttempts: number;
};

export type EscalationAttempt = {
  at: number;
  channel: Channel;
  contact: string;
  status: "sent" | "failed";
};

export type EscalationDecision =
  | { action: "stop"; reason: "acknowledged" | "exhausted" | "no_policy" }
  | { action: "wait"; reason: "rate_limited"; retryAt: number }
  | { action: "send"; channel: Channel; contact: string; attempt: number };

/**
 * Next page of an escalation. Acknowledgement wins over any remaining retries.
 * A later send waits until minIntervalMs after the previous attempt on that step.
 */
export function decideEscalation(input: {
  steps: EscalationStep[];
  severity: string;
  acknowledged: boolean;
  attempts: EscalationAttempt[];
  now: number;
}): EscalationDecision {
  if (input.acknowledged) return { action: "stop", reason: "acknowledged" };
  const steps = input.steps.filter((s) => s.severity === input.severity);
  if (!steps.length) return { action: "stop", reason: "no_policy" };

  const counted = input.attempts.filter((a) => a.status === "sent" || a.status === "failed");
  const last = counted.reduce((max, a) => Math.max(max, a.at), 0);

  for (const step of steps) {
    for (const contact of step.contacts) {
      const n = counted.filter((a) => a.channel === step.channel && a.contact === contact).length;
      if (n >= step.maxAttempts) continue;
      if (last && input.now - last < step.minIntervalMs) {
        return { action: "wait", reason: "rate_limited", retryAt: last + step.minIntervalMs };
      }
      return { action: "send", channel: step.channel, contact, attempt: n + 1 };
    }
  }
  return { action: "stop", reason: "exhausted" };
}
