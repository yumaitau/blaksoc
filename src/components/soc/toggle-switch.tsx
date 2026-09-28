"use client";
import { cn } from "@/lib/utils";

/** Accessible on/off switch (role="switch"). The caller owns state and persistence. */
export function ToggleSwitch({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn("relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 disabled:opacity-50", checked ? "border-accent bg-accent" : "border-border-strong bg-surface-2")}
    >
      <span className={cn("block size-3.5 rounded-full bg-fg transition-transform", checked ? "translate-x-[18px]" : "translate-x-0.5")} />
    </button>
  );
}
