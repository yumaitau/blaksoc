import type { ReportContent } from "@/lib/reports/types";
import type { AssessmentResult } from "./score";

export function buildAssessmentReport(tenantName: string, result: AssessmentResult): ReportContent {
  const trend = result.ratings.map((row) => {
    const previous = result.previous ? `ML${result.previous.levels[row.strategy]}` : "none";
    return `${row.label}: previous ${previous}, now ML${row.level} (${result.trend[row.strategy]}). ${row.telemetry}`;
  }).join("\n");
  const plan = result.remediation.length
    ? result.remediation.map((item, index) => `${index + 1}. ${item.title}\nOwner: ${item.owner}. Due: ${item.dueAt.slice(0, 10)}. Priority: ${item.priority}.`).join("\n\n")
    : "No gaps at the level that failed.";
  return {
    tenantName,
    generatedAt: new Date().toISOString(),
    period: { start: result.assessedAt, end: result.nextDue },
    sections: [
      { heading: "Disclaimer", basis: "interpretation", author: "system", body: `${result.disclaimer}\n\n${result.model}` },
      { heading: "Re-assessment", basis: "observed", body: `Run this again every ${result.cadenceDays} days. Next due ${result.nextDue.slice(0, 10)}. Owner: ${result.owner}.` },
      { heading: "Trend", basis: "observed", body: trend },
      ...result.ratings.map((row) => ({
        heading: `${row.label}: ML${row.level}`,
        basis: "observed" as const,
        body: [`Telemetry: ${row.telemetry}`, ...row.lines.map((line) => `ML${line.minLevel}. ${line.text}\nAnswer: ${line.answer}. Met: ${line.met ? "yes" : "no"}.\nEvidence: ${line.evidence.detail}`)].join("\n\n"),
      })),
      { heading: "Remediation plan", basis: "observed", body: plan },
    ],
  };
}
