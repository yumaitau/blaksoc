"use client";
import { Building2, ChevronsUpDown } from "lucide-react";
import { useTransition } from "react";
import { setWorkspace } from "@/app/(app)/workspace-actions";

export function WorkspaceSwitcher({ tenants, current }: { tenants: { id: string; name: string }[]; current: string }) {
  const [pending, start] = useTransition();
  return (
    <label className="relative inline-flex w-full min-w-0 max-w-full items-center gap-2 rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm hover:border-border-strong md:w-auto md:max-w-xs">
      <Building2 className="size-4 shrink-0 text-accent" />
      <span className="sr-only">Customer workspace</span>
      <select
        className="w-full min-w-0 appearance-none bg-transparent pr-5 font-medium outline-none md:w-auto"
        value={current}
        disabled={pending}
        onChange={(e) => start(() => setWorkspace(e.target.value))}
      >
        <option value="all">All customers</option>
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>{t.name}</option>
        ))}
      </select>
      <ChevronsUpDown className="pointer-events-none absolute right-2 size-3.5 text-faint" />
    </label>
  );
}
