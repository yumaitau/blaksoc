export type ReportLink = { label: string; href: string };

export type ReportSection = {
  heading: string;
  /** observed = facts from telemetry/records; interpretation = analyst or AI judgement. */
  basis: "observed" | "interpretation";
  author?: "analyst" | "ai" | "system";
  body?: string;
  table?: { columns: string[]; rows: (string | number)[][] };
  /** Staff paths to the records behind this section. */
  links?: ReportLink[];
  /** False for text the organisation wrote. Reading age covers generated text only. */
  scored?: boolean;
};

export type ReportImage = { mime: "image/png" | "image/jpeg"; data: string };

export type BoardLight = "steady" | "look" | "now";

export type ReportContent = {
  tenantName: string;
  generatedAt: string;
  period: { start: string; end: string };
  sections: ReportSection[];
  /** Set on the board one-pager. Other reports leave this unset. */
  audience?: "board";
  light?: BoardLight;
  /** Set only when the organisation stored an image. Never a default picture. */
  image?: ReportImage | null;
  /** Partner name beside blakSOC. Absent when Yuma IT holds the customer directly. */
  cobrand?: string | null;
};
