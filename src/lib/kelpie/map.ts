import type { KelpieCreateCase, KelpieObservableType, KelpieSeverity, KelpieStatus } from "./client";
import { detectionContext, type DetectionAlert } from "@/lib/incidents/explanation";

export const SOURCE_SYSTEM = "blaksoc";

type IncidentStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "ERADICATED" | "RECOVERED" | "CLOSED";
type Severity = "informational" | "low" | "medium" | "high" | "critical";

const STATUS: Record<KelpieStatus, IncidentStatus> = {
  open: "OPEN",
  in_progress: "INVESTIGATING",
  contained: "CONTAINED",
  eradicated: "ERADICATED",
  recovered: "RECOVERED",
  closed: "CLOSED",
};

export function incidentStatusFor(status: string): IncidentStatus | null {
  return STATUS[status as KelpieStatus] ?? null;
}

export function kelpieSeverity(s: Severity): KelpieSeverity {
  return s === "informational" ? "low" : s;
}

export type IncidentForCase = {
  id: string;
  ref: number;
  title: string;
  description: string | null;
  severity: Severity;
  attackTechniques: string[];
  createdAt: Date;
  firstSeen: Date | null;
  tenantSlug: string;
  links: { kind: string; label: string }[];
  alerts?: DetectionAlert[];
};

/** Case body for one incident. The incident id is the idempotency key, so a retry never makes a second case. */
export function caseFromIncident(inc: IncidentForCase, appUrl: string): KelpieCreateCase {
  const assets = inc.links.filter((l) => l.kind === "asset").map((l) => l.label);
  const people = inc.links.filter((l) => l.kind === "identity").map((l) => l.label);
  const lines = [
    inc.description ?? "",
    `blakSOC incident INC-${inc.ref}.`,
    assets.length ? `Assets: ${assets.join(", ")}.` : "",
    people.length ? `Identities: ${people.join(", ")}.` : "",
    inc.attackTechniques.length ? `ATT&CK: ${inc.attackTechniques.join(", ")}.` : "",
  ].filter(Boolean);
  const detected = inc.createdAt.toISOString();
  const occurred = inc.firstSeen && inc.firstSeen <= inc.createdAt ? inc.firstSeen.toISOString() : detected;
  return {
    title: inc.title.slice(0, 500),
    summary: [lines.join("\n").slice(0, 10_000), detectionContext(inc.alerts ?? [], appUrl)].filter(Boolean).join("\n\n"),
    severity: kelpieSeverity(inc.severity),
    tlp: "amber",
    // Kelpie asks producers to send "other" rather than guess a classification.
    classification: "other",
    occurredAt: occurred,
    detectedAt: detected,
    tags: [`blaksoc:INC-${inc.ref}`, `tenant:${inc.tenantSlug}`, ...inc.attackTechniques.map((t) => `attack:${t}`), ...assets.map((a) => `host:${a}`)].slice(0, 50),
    sourceSystem: SOURCE_SYSTEM,
    sourceReference: inc.id,
    sourceUrl: `${appUrl.replace(/\/+$/, "")}/soc/incidents/${inc.id}`,
  };
}

const OBSERVABLE: Record<string, KelpieObservableType> = {
  ipv4: "ip", ipv6: "ip", domain: "domain", url: "url", md5: "file_hash", sha1: "file_hash", sha256: "file_hash",
  email: "email", hostname: "hostname", user: "username",
};

/** blakSOC observable link refId is `type:value`. CVEs and unknown types go as `other`. */
export function kelpieObservable(refId: string): { type: KelpieObservableType; value: string } | null {
  const i = refId.indexOf(":");
  if (i <= 0) return null;
  const value = refId.slice(i + 1).trim();
  if (!value) return null;
  return { type: OBSERVABLE[refId.slice(0, i)] ?? "other", value: value.slice(0, 2048) };
}
