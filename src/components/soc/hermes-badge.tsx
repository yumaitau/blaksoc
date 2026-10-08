import { Bot } from "lucide-react";
import { cn } from "@/lib/utils";

export const HERMES_TITLE = "Action taken automatically by Hermes, blakSOC's AI noise analyst";
export const HERMES_NOTE_TITLE = "Written by Hermes, blakSOC's AI noise analyst. Interpretation, not evidence.";

/**
 * Hermes' mark, wherever it acted or wrote: the bot icon, its name and an "AI" chip in the Hermes colour
 * (no other badge uses it). `sm` for dense rows and secondary markers.
 */
export function HermesBadge({ label = "Hermes", size = "md", title = HERMES_TITLE, className }: { label?: string; size?: "md" | "sm"; title?: string; className?: string }) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded border border-hermes/35 bg-hermes/15 font-medium leading-none text-hermes",
        size === "sm" ? "px-1 py-0.5 text-[10.5px]" : "px-1.5 py-0.5 text-[11px]",
        className,
      )}
    >
      <Bot aria-hidden className={size === "sm" ? "size-3" : "size-3.5"} />
      {label}
      <span className="rounded-sm bg-hermes px-[3px] py-px text-[9px] font-bold tracking-wide text-hermes-fg">AI</span>
    </span>
  );
}

/** A prominent notice that Hermes acted on this record: what, when, why, and how to reverse it (`actions`). */
export function HermesBanner({ title, children, actions, muted, className }: { title: React.ReactNode; children?: React.ReactNode; actions?: React.ReactNode; muted?: boolean; className?: string }) {
  return (
    <section
      role="note"
      title={HERMES_TITLE}
      className={cn(
        "flex flex-wrap items-start justify-between gap-3 rounded-lg border border-l-4 px-4 py-3 text-sm",
        muted ? "border-border border-l-hermes/50 bg-surface-2" : "border-hermes/40 border-l-hermes bg-hermes/10",
        className,
      )}
    >
      <div className="flex min-w-0 items-start gap-3">
        <span aria-hidden className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-full bg-hermes/20 text-hermes">
          <Bot className="size-4" />
        </span>
        <div className="min-w-0 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <HermesBadge />
            <span className="font-medium">{title}</span>
          </div>
          {children ? <div className="space-y-0.5 text-xs text-muted">{children}</div> : null}
        </div>
      </div>
      {actions ? <div className="shrink-0">{actions}</div> : null}
    </section>
  );
}
