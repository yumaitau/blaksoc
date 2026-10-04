export type ResponseHint = { ruleId?: string; grantId?: string; process?: string };

/**
 * Response targets a provider left on the alert's raw payload: M365 inbox rule / OAuth grant ids,
 * and `raw.process.pid` for endpoint agents that know the offending process (e.g. Tawny).
 */
export function responseHintOf(raw: unknown): ResponseHint | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as { ruleId?: string; grantId?: string; process?: { pid?: unknown } };
  const pid = typeof r.process?.pid === "number" ? String(r.process.pid) : undefined;
  return r.ruleId || r.grantId || pid ? { ruleId: r.ruleId, grantId: r.grantId, process: pid } : undefined;
}
