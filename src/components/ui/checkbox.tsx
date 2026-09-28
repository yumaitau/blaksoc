"use client";
import * as C from "@radix-ui/react-checkbox";
import { Check, Minus } from "lucide-react";
import * as React from "react";
import { cn } from "@/lib/utils";

export function Checkbox({ className, ...p }: React.ComponentProps<typeof C.Root>) {
  return (
    <C.Root className={cn("peer inline-flex size-4 shrink-0 items-center justify-center rounded-[4px] border border-border-strong bg-bg data-[state=checked]:border-accent data-[state=checked]:bg-accent data-[state=indeterminate]:bg-accent text-accent-fg", className)} {...p}>
      <C.Indicator>{p.checked === "indeterminate" ? <Minus className="size-3" /> : <Check className="size-3" />}</C.Indicator>
    </C.Root>
  );
}
