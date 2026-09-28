import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const RTF = new Intl.RelativeTimeFormat("en-AU", { numeric: "auto" });

export function timeAgo(d: Date | string | null | undefined): string {
  if (!d) return "—";
  const date = typeof d === "string" ? new Date(d) : d;
  const s = Math.round((date.getTime() - Date.now()) / 1000);
  const abs = Math.abs(s);
  if (abs < 60) return RTF.format(s, "second");
  if (abs < 3600) return RTF.format(Math.round(s / 60), "minute");
  if (abs < 86400) return RTF.format(Math.round(s / 3600), "hour");
  return RTF.format(Math.round(s / 86400), "day");
}

const DT = new Intl.DateTimeFormat("en-AU", { dateStyle: "medium", timeStyle: "short", timeZone: "Australia/Sydney" });
const T = new Intl.DateTimeFormat("en-AU", { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "Australia/Sydney" });

/** Displayed in Australia/Sydney; stored as UTC. */
export function fmtDateTime(d: Date | string | null | undefined): string {
  return d ? DT.format(typeof d === "string" ? new Date(d) : d) : "—";
}

export function fmtTime(d: Date | string | null | undefined): string {
  return d ? T.format(typeof d === "string" ? new Date(d) : d) : "—";
}
