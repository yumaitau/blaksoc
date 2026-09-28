"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

export function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  const path = usePathname();
  // Exact match for section roots that have sibling routes underneath.
  const exact = ["/soc", "/detections", "/admin"].includes(href);
  const active = exact ? path === href : path === href || path.startsWith(`${href}/`);
  return (
    <Link href={href} className={cn("flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors", active ? "bg-accent-soft text-fg [&_svg]:text-accent" : "text-muted hover:bg-surface-2 hover:text-fg")}>
      {children}
    </Link>
  );
}
