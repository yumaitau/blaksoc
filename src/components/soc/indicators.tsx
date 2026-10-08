import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import Link from "next/link";
import type { RiskFactor } from "@/db/schema";
import { cn } from "@/lib/utils";

const SEV = {
  critical: { label: "Critical", cls: "bg-sev-critical/15 text-sev-critical", dot: "bg-sev-critical" },
  high: { label: "High", cls: "bg-sev-high/15 text-sev-high", dot: "bg-sev-high" },
  medium: { label: "Medium", cls: "bg-sev-medium/15 text-sev-medium", dot: "bg-sev-medium" },
  low: { label: "Low", cls: "bg-sev-low/15 text-sev-low", dot: "bg-sev-low" },
  informational: { label: "Info", cls: "bg-sev-info/15 text-sev-info", dot: "bg-sev-info" },
} as const;

export type SeverityKey = keyof typeof SEV;

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  const s = SEV[severity as SeverityKey] ?? SEV.informational;
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide", s.cls, className)}>
      <span className={cn("size-1.5 rounded-full", s.dot)} />
      {s.label}
    </span>
  );
}

export function riskTone(score: number) {
  return score >= 80 ? "text-sev-critical" : score >= 60 ? "text-sev-high" : score >= 40 ? "text-sev-medium" : score >= 20 ? "text-sev-low" : "text-sev-info";
}

/** 0–100 risk with a bar. Factors are shown in a native tooltip; the detail page lists them in full. */
/** "+6", "−10": risk points with their sign. */
const signed = (n: number) => (n < 0 ? `−${-n}` : `+${n}`);

export function RiskScore({ score, factors, className }: { score: number; factors?: RiskFactor[]; className?: string }) {
  const title = factors?.length ? factors.map((f) => `${signed(f.points)} ${f.label}: ${f.evidence}`).join("\n") : undefined;
  return (
    <span className={cn("inline-flex items-center gap-2", className)} title={title}>
      <span className={cn("num w-7 text-right text-sm font-semibold", riskTone(score))}>{score}</span>
      <span className="h-1 w-12 overflow-hidden rounded-full bg-surface-2">
        <span className={cn("block h-full rounded-full", score >= 80 ? "bg-sev-critical" : score >= 60 ? "bg-sev-high" : score >= 40 ? "bg-sev-medium" : "bg-sev-low")} style={{ width: `${score}%` }} />
      </span>
    </span>
  );
}

/** Explains a score: every contributing factor with its evidence and, where possible, a link to the backing record. */
export function RiskFactors({ factors, total }: { factors: RiskFactor[]; total: number }) {
  return (
    <div className="space-y-1.5">
      {factors.map((f) => (
        <div key={f.key} className="flex items-start gap-3 text-sm">
          <span className={cn("num w-9 shrink-0 text-right font-semibold", f.points < 0 ? "text-ok" : "text-accent")}>{signed(f.points)}</span>
          <div className="min-w-0">
            <div className="font-medium">{f.label}</div>
            <div className="text-xs text-muted">
              {f.evidence}
              {f.ref ? <> · <RefLink type={f.ref.type} id={f.ref.id} /></> : null}
            </div>
          </div>
        </div>
      ))}
      <div className="flex items-center gap-3 border-t border-border pt-1.5 text-sm">
        <span className={cn("num w-9 text-right font-bold", riskTone(total))}>{total}</span>
        <span className="text-muted">blakSOC risk (sum, capped at 100). No model output contributes to this score.</span>
      </div>
    </div>
  );
}

export function RefLink({ type, id, label }: { type: string; id: string; label?: string }) {
  const href = type === "asset" ? `/assets/${id}` : type === "alert" ? `/soc/alerts/${id}` : type === "incident" ? `/soc/incidents/${id}` : type === "opencti" ? `/intel?q=${encodeURIComponent(id)}` : type === "rule" ? `/detections/rules/${id}` : type === "cve" ? `/vulnerabilities?cve=${id}` : type === "attack" ? `/detections/attack?t=${id}` : null;
  const text = label ?? `${type}:${id.length > 12 ? `${id.slice(0, 8)}…` : id}`;
  return href ? <Link href={href} className="text-accent hover:underline">{text}</Link> : <span>{text}</span>;
}

export function IntelVerdict({ verdict, compact }: { verdict: string; compact?: boolean }) {
  if (verdict === "malicious")
    return <span className="inline-flex items-center gap-1 text-xs font-medium text-sev-critical"><ShieldAlert className="size-3.5" />{compact ? "" : "Malicious"}</span>;
  if (verdict === "suspicious")
    return <span className="inline-flex items-center gap-1 text-xs font-medium text-sev-medium"><ShieldQuestion className="size-3.5" />{compact ? "" : "Suspicious"}</span>;
  if (verdict === "benign") return <span className="inline-flex items-center gap-1 text-xs text-ok"><ShieldCheck className="size-3.5" />{compact ? "" : "Benign"}</span>;
  return <span className="text-xs text-faint">{verdict === "unchecked" ? "—" : "No match"}</span>;
}

const STATUS_TONE: Record<string, string> = {
  NEW: "bg-accent-soft text-accent",
  TRIAGING: "bg-sev-low/15 text-sev-low",
  INVESTIGATING: "bg-intel/15 text-intel",
  ESCALATED: "bg-sev-high/15 text-sev-high",
  CONTAINED: "bg-ok/15 text-ok",
  RESOLVED: "bg-surface-2 text-muted",
  FALSE_POSITIVE: "bg-surface-2 text-faint",
  OPEN: "bg-accent-soft text-accent",
  ERADICATED: "bg-ok/15 text-ok",
  RECOVERED: "bg-ok/15 text-ok",
  CLOSED: "bg-surface-2 text-faint",
  AWAITING_APPROVAL: "bg-warn/15 text-warn",
  PENDING: "bg-warn/15 text-warn",
  APPROVED: "bg-ok/15 text-ok",
  REJECTED: "bg-danger/15 text-danger",
  EXECUTING: "bg-intel/15 text-intel",
  SUCCEEDED: "bg-ok/15 text-ok",
  FAILED: "bg-danger/15 text-danger",
  RUNNING: "bg-intel/15 text-intel",
  WAITING_APPROVAL: "bg-warn/15 text-warn",
  CANCELLED: "bg-surface-2 text-faint",
};

export function StatusBadge({ status }: { status: string }) {
  return <span className={cn("inline-flex rounded px-1.5 py-0.5 text-[11px] font-medium tracking-wide whitespace-nowrap", STATUS_TONE[status] ?? "bg-surface-2 text-muted")}>{status.replaceAll("_", " ")}</span>;
}

export function AttackChips({ techniques, max = 3 }: { techniques: string[]; max?: number }) {
  if (!techniques.length) return <span className="text-xs text-faint">—</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {techniques.slice(0, max).map((t) => (
        <Link key={t} href={`/detections/attack?t=${t}`} className="rounded border border-border px-1 font-mono text-[10.5px] text-muted hover:border-accent hover:text-accent">
          {t}
        </Link>
      ))}
      {techniques.length > max ? <span className="text-[10.5px] text-faint">+{techniques.length - max}</span> : null}
    </span>
  );
}

export function PageHeader({ title, description, actions, eyebrow }: { title: string; description?: string; actions?: React.ReactNode; eyebrow?: string }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
      <div>
        {eyebrow ? <div className="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">{eyebrow}</div> : null}
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-sm text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border px-6 py-10 text-center">
      <div className="text-sm font-medium">{title}</div>
      {children ? <div className="mt-1 max-w-md text-sm text-muted">{children}</div> : null}
    </div>
  );
}

/** A metric that is also a link to the queue that acts on it — no vanity numbers. */
export function StatLink({ label, value, href, tone, hint }: { label: string; value: number | string; href: string; tone?: "danger" | "warn" | "intel" | "ok"; hint?: string }) {
  const t = tone === "danger" ? "text-sev-critical" : tone === "warn" ? "text-sev-medium" : tone === "intel" ? "text-intel" : tone === "ok" ? "text-ok" : "text-fg";
  return (
    <Link href={href} className="group rounded-lg border border-border bg-surface px-4 py-3 transition-colors hover:border-border-strong">
      <div className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</div>
      <div className={cn("num mt-1 text-2xl font-semibold", t)}>{value}</div>
      {hint ? <div className="mt-0.5 text-xs text-muted group-hover:text-fg">{hint} →</div> : null}
    </Link>
  );
}
