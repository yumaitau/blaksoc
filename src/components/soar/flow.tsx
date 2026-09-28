import { ArrowRight, Lock } from "lucide-react";
import type { PlaybookStep, PlaybookTrigger } from "@/db/schema";
import { cn } from "@/lib/utils";

export type CatalogueEntry = { key: string; label: string; destructive: boolean };

export const EVENT_LABELS: Record<PlaybookTrigger["event"], string> = {
  "alert.created": "Alert created",
  "alert.enriched": "Alert enriched",
  "incident.created": "Incident created",
  manual: "Manual run only",
};

export const OP_LABELS: Record<string, string> = { eq: "equals", neq: "does not equal", gte: "≥", lte: "≤", in: "is one of", contains: "contains" };

export function fmtValue(v: unknown): string {
  return Array.isArray(v) ? v.join(", ") : typeof v === "string" ? v : JSON.stringify(v);
}

export function conditionText(c: { field: string; op: string; value: unknown }) {
  return `${c.field} ${OP_LABELS[c.op] ?? c.op} ${fmtValue(c.value)}`;
}

export function isDestructive(action: string, catalogue: CatalogueEntry[]) {
  return catalogue.find((c) => c.key === action)?.destructive ?? false;
}

/** A step that always waits for a human (destructive, explicitly gated, or an approval step). */
export function isGated(s: Pick<PlaybookStep, "action" | "requireApproval">, catalogue: CatalogueEntry[]) {
  return isDestructive(s.action, catalogue) || !!s.requireApproval || s.action === "approval.request";
}

export function HumanApprovalBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn("inline-flex items-center gap-1 rounded bg-warn/15 px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap text-warn", className)}
      title="Containment never runs autonomously unless a platform administrator enabled auto-containment for this customer. AI can never auto-approve."
    >
      <Lock className="size-3" aria-hidden />
      Human approval required
    </span>
  );
}

export const APPROVAL_EXPLAINER =
  "Containment actions never run autonomously. They wait for a human approver unless a platform administrator has enabled auto-containment for that customer. AI-requested actions can never be auto-approved.";

/** Trigger → Conditions → Actions → Approval → Execution, derived from the playbook definition. */
export function FlowPreview({ trigger, steps, catalogue }: { trigger: PlaybookTrigger; steps: PlaybookStep[]; catalogue: CatalogueEntry[] }) {
  const label = (a: string) => catalogue.find((c) => c.key === a)?.label ?? a;
  const auto = steps.filter((s) => !isDestructive(s.action, catalogue) && s.action !== "approval.request");
  const gates = steps.filter((s) => isGated(s, catalogue));
  const execution = steps.filter((s) => isDestructive(s.action, catalogue));
  const stages: { title: string; tone?: string; items: string[]; empty: string }[] = [
    { title: "Trigger", items: [EVENT_LABELS[trigger.event] ?? trigger.event], empty: "" },
    { title: "Conditions", items: trigger.conditions.map(conditionText), empty: "Always (no conditions)" },
    { title: "Actions", items: auto.map((s) => `${s.name}${s.when ? " (conditional)" : ""}`), empty: "No automated steps" },
    { title: "Approval", tone: gates.length ? "border-warn/50" : undefined, items: gates.map((s) => s.name), empty: "No human gate" },
    { title: "Execution", tone: execution.length ? "border-danger/50" : undefined, items: execution.map((s) => label(s.action)), empty: "No containment" },
  ];
  return (
    <ol className="flex flex-col gap-2 lg:flex-row lg:items-stretch" aria-label="Playbook flow">
      {stages.map((st, i) => (
        <li key={st.title} className="flex min-w-0 flex-1 items-center gap-2">
          <div className={cn("h-full min-w-0 flex-1 rounded-md border border-border bg-bg px-3 py-2", st.tone)}>
            <div className="text-[10.5px] font-semibold uppercase tracking-wider text-faint">{i + 1}. {st.title}</div>
            {st.items.length ? (
              <ul className="mt-1 space-y-0.5">
                {st.items.slice(0, 5).map((t, j) => <li key={j} className="truncate text-xs" title={t}>{t}</li>)}
                {st.items.length > 5 ? <li className="text-[11px] text-faint">+{st.items.length - 5} more</li> : null}
              </ul>
            ) : (
              <div className="mt-1 text-xs text-faint">{st.empty}</div>
            )}
          </div>
          {i < stages.length - 1 ? <ArrowRight className="hidden size-4 shrink-0 text-faint lg:block" aria-hidden /> : null}
        </li>
      ))}
    </ol>
  );
}
