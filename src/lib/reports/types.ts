export type ReportSection = {
  heading: string;
  /** observed = facts from telemetry/records; interpretation = analyst or AI judgement. */
  basis: "observed" | "interpretation";
  author?: "analyst" | "ai" | "system";
  body?: string;
  table?: { columns: string[]; rows: (string | number)[][] };
};

export type ReportContent = {
  tenantName: string;
  generatedAt: string;
  period: { start: string; end: string };
  sections: ReportSection[];
};
