"use client";
import * as M from "@radix-ui/react-dropdown-menu";
import * as React from "react";
import { cn } from "@/lib/utils";

export const DropdownMenu = M.Root;
export const DropdownMenuTrigger = M.Trigger;
export function DropdownMenuContent({ className, ...p }: React.ComponentProps<typeof M.Content>) {
  return (
    <M.Portal>
      <M.Content sideOffset={6} className={cn("z-50 min-w-48 rounded-md border border-border bg-surface p-1 shadow-xl", className)} {...p} />
    </M.Portal>
  );
}
export function DropdownMenuItem({ className, ...p }: React.ComponentProps<typeof M.Item>) {
  return <M.Item className={cn("flex cursor-pointer select-none items-center gap-2 rounded px-2 py-1.5 text-sm text-fg outline-none data-[highlighted]:bg-surface-2", className)} {...p} />;
}
export function DropdownMenuLabel({ className, ...p }: React.ComponentProps<typeof M.Label>) {
  return <M.Label className={cn("px-2 py-1.5 text-[11px] uppercase tracking-wider text-faint", className)} {...p} />;
}
export const DropdownMenuSeparator = (p: React.ComponentProps<typeof M.Separator>) => <M.Separator className="my-1 h-px bg-border" {...p} />;
