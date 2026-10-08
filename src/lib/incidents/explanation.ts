/** Evidence-based incident context shared by the SOC view and Kelpie export. */
export type DetectionAlert = {
  id: string;
  title: string;
  source: string;
  ruleId: string | null;
  severity: string;
  siemSeverity: number | null;
  occurredAt: Date;
  assetName: string | null;
  userName: string | null;
  description: string | null;
  raw: unknown;
  groupReason?: { summary: string } | null;
  wazuhUrl?: string | null;
  contributing?: DetectionAlert[];
};

function object(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
function value(raw: unknown, path: string): string | null {
  const result = path.split(".").reduce<unknown>((v, key) => object(v)[key], raw);
  return typeof result === "string" && result.trim() ? result : typeof result === "number" ? String(result) : null;
}

export function explainDetection(a: DetectionAlert) {
  const raw = object(a.raw);
  const host = a.assetName ?? value(raw, "agent.name") ?? value(raw, "hostname") ?? value(raw, "correlation.entity.host");
  const rule = value(raw, "rule.description") ?? a.title;
  const groups = object(raw.rule).groups;
  const hasGroup = (pattern: RegExp) => Array.isArray(groups) && groups.some((g) => typeof g === "string" && pattern.test(g));
  let meaning = "A detection rule matched this event. The alert needs investigation before it can be treated as a confirmed security incident.";
  let nextStep = "Review the original event, confirm whether the activity was expected, and check related events on the same host or account.";
  if (a.source === "blaksoc-correlation") {
    meaning = "blakSOC combined several source alerts using a correlation rule. This is a blakSOC finding, not a separate Wazuh alert; its priority can differ from the source alerts.";
    nextStep = "Review the contributing alerts below and the correlation condition. Confirm that the events form a meaningful pattern rather than repeated routine activity.";
    if (a.ruleId === "host-risk-accumulation" || a.ruleId === "user-risk-accumulation") {
      meaning = "blakSOC added the risk scores of alerts on this host or account over 24 hours and the total reached 150. Repeated low or medium alerts can reach this threshold. Volume alone does not establish a high-severity threat.";
      nextStep = "Review the contributing Wazuh rules and events. Check whether repeated events are expected. This rule is now a medium-priority review signal and cannot automatically open an incident; older cases may retain their original priority.";
    }
  } else if (raw.syscheck || hasGroup(/^(syscheck|fim)/)) {
    meaning = "Wazuh detected a change to a monitored file or directory. Software updates and authorised administration can also cause these alerts.";
    nextStep = "Check the file path and what changed, then compare the time with deployments or approved maintenance. Investigate changes that cannot be explained.";
  } else if (object(raw.data).vulnerability || hasGroup(/vulnerability/)) {
    meaning = "Wazuh identified a reported software vulnerability on this host. This finding does not by itself show that the vulnerability was exploited.";
    nextStep = "Verify the affected package and version, check whether a fix is available, and assess the host's exposure before prioritising remediation.";
  } else if (object(raw.data).sca || hasGroup(/^sca$/)) {
    meaning = "A security configuration assessment reported a check result. Review the check's result and rationale to understand the configuration risk.";
    nextStep = "Read the policy check, expected setting and remediation. Confirm whether the setting is intentional or needs correction.";
  } else if (hasGroup(/authentication_failed|invalid_login/)) {
    meaning = "An authentication attempt failed. This can be a mistyped password, a stale service credential, or an attempt to gain access.";
    nextStep = "Check the account, source address and frequency. Look for successful sign-ins from the same source and confirm the activity with the account owner.";
  } else if (hasGroup(/authentication_success/)) {
    meaning = "Wazuh recorded a successful authentication that matched a detection rule. A successful login alone does not establish unauthorised access.";
    nextStep = "Confirm the account, source address and login time were expected, and review the actions taken after login.";
  }
  const fields = [
    ["File", "syscheck.path"], ["Change", "syscheck.event"],
    ["CVE", "data.vulnerability.cve"], ["Package", "data.vulnerability.package.name"],
    ["Version", "data.vulnerability.package.version"], ["Status", "data.vulnerability.status"],
    ["Policy", "data.sca.policy"], ["Check", "data.sca.check.title"], ["Result", "data.sca.check.result"],
    ["Rationale", "data.sca.check.rationale"], ["Remediation", "data.sca.check.remediation"],
    ["Source IP", "data.srcip"], ["Destination IP", "data.dstip"],
    ["Command", "data.command"], ["Process", "data.win.eventdata.image"],
    ["Command line", "data.win.eventdata.commandLine"], ["Location", "location"],
  ].flatMap(([label, path]) => {
    const text = value(raw, path!);
    return text ? [{ label: label!, value: text.slice(0, 1000) }] : [];
  });
  return {
    host, rule, meaning, nextStep, fields,
    trigger: `${a.source === "wazuh" ? "Wazuh" : a.source === "blaksoc-correlation" ? "blakSOC correlation" : a.source} ${a.ruleId ? `rule ${a.ruleId}` : "detection"} matched${host ? ` on ${host}` : ""}: ${rule}`,
    evidence: (value(raw, "full_log") ?? a.description)?.slice(0, 4000) ?? null,
  };
}

// These delimiters let the worker refresh only its own section of a Kelpie summary.
export const CONTEXT_START = "[blakSOC detection context]";
export const CONTEXT_END = "[/blakSOC detection context]";
const clean = (text: string) => text.replaceAll(CONTEXT_START, "").replaceAll(CONTEXT_END, "");
const line = (text: string, max = 1000) => clean(text).replace(/\s+/g, " ").slice(0, max);

export function detectionContext(alerts: DetectionAlert[], appUrl: string): string {
  const lines = ["Why this incident needs attention", alerts.length
    ? `${alerts.length} linked alert${alerts.length === 1 ? "" : "s"}. These are detection findings; confirm the cause and impact during investigation.`
    : "No source alerts are linked. Review the case description and timeline to establish why this incident was opened."];
  const expanded = [...new Map(alerts.flatMap((a) => [a, ...(a.contributing ?? [])]).map((a) => [a.id, a])).values()];
  let shown = 0;
  for (const a of expanded.slice(0, 10)) {
    const e = explainDetection(a);
    const section = [line(e.trigger), `What this means: ${e.meaning}`,
      `Occurred: ${a.occurredAt.toISOString()}${a.userName ? ` | Account: ${line(a.userName, 200)}` : ""}`,
      `Priority: ${a.severity}${a.siemSeverity != null ? ` | Wazuh rule level: ${a.siemSeverity}/15` : ""}`,
      ...e.fields.slice(0, 6).map((f) => `${f.label}: ${line(f.value, 300)}`),
      ...(a.groupReason ? [`Why grouped: ${line(a.groupReason.summary, 400)}`] : []),
      `Check next: ${e.nextStep}`,
      `blakSOC alert: ${appUrl.replace(/\/+$/, "")}/soc/alerts/${a.id}`,
      ...(a.wazuhUrl ? [`Wazuh alert: ${a.wazuhUrl}`] : [])];
    if (e.evidence) section.push(`Event excerpt: ${line(e.evidence, 800)}`);
    if (lines.join("\n").length + section.join("\n").length > 35_000) break;
    lines.push("", ...section);
    shown++;
  }
  if (expanded.length > shown) lines.push("", `Showing ${shown} of ${expanded.length} linked and contributing alerts. Open the source incident in blakSOC for the complete list.`);
  return `${CONTEXT_START}\n${clean(lines.join("\n"))}\n${CONTEXT_END}`;
}

/** Preserve analyst text and use the remote case version when saving the result. */
export function mergeDetectionContext(summary: string | null | undefined, context: string): string {
  const current = summary ?? "";
  const start = current.indexOf(CONTEXT_START);
  const end = start < 0 ? -1 : current.indexOf(CONTEXT_END, start);
  if (start >= 0 && end >= 0) return current.slice(0, start) + context + current.slice(end + CONTEXT_END.length);
  return [current, context].filter(Boolean).join("\n\n");
}
