"use client";
import * as D from "@radix-ui/react-dialog";
import { AlertTriangle, ArrowRight, Bug, ExternalLink, FolderKanban, Newspaper, Search, Server } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useId, useMemo, useRef, useState, useTransition } from "react";
import { paletteSearch } from "@/app/(app)/search-actions";
import type { QuickHit } from "@/lib/services/quick-search";
import { cn } from "@/lib/utils";

export type PalettePage = { href: string; label: string; group: string };
type Item = { key: string; title: string; detail: string; href: string; external?: boolean; icon: React.ComponentType<{ className?: string }>; section: string };

const KIND: Record<QuickHit["kind"], { icon: Item["icon"]; section: string }> = {
  incident: { icon: FolderKanban, section: "Incidents" },
  asset: { icon: Server, section: "Assets" },
  cve: { icon: Bug, section: "Vulnerabilities" },
  alert: { icon: AlertTriangle, section: "Alerts" },
  advisory: { icon: Newspaper, section: "Advisories" },
};

/** ⌘K / Ctrl+K: jump to any page, or find an asset, alert, incident, CVE or advisory in the current workspace. */
export function CommandPalette({ pages }: { pages: PalettePage[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<{ q: string; items: QuickHit[]; error?: string }>({ q: "", items: [] });
  const [active, setActive] = useState(0);
  const [pending, start] = useTransition();
  const listId = useId();
  const listRef = useRef<HTMLDivElement>(null);
  const latest = useRef("");
  const change = (value: string) => {
    latest.current = value.trim();
    setQ(value);
    setActive(0);
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Debounced server lookup; a stale answer for an older query is dropped.
  useEffect(() => {
    const term = q.trim();
    if (term.length < 2) return;
    const t = setTimeout(() => {
      start(async () => {
        const res = await paletteSearch(term);
        if (latest.current === term) setHits({ q: term, items: res.ok ? (res.data ?? []) : [], error: res.ok ? undefined : res.error });
      });
    }, 180);
    return () => clearTimeout(t);
  }, [q]);

  const items = useMemo<Item[]>(() => {
    const term = q.trim().toLowerCase();
    const pageItems = pages
      .filter((p) => !term || p.label.toLowerCase().includes(term) || p.group.toLowerCase().includes(term))
      .slice(0, term ? 6 : 20)
      .map((p): Item => ({ key: `page:${p.href}`, title: p.label, detail: p.group, href: p.href, icon: ArrowRight, section: "Go to" }));
    const records = term.length >= 2 && hits.q === q.trim() ? hits.items.map((h, i): Item => ({ key: `${h.kind}:${i}:${h.href}`, ...h, ...KIND[h.kind] })) : [];
    return [...pageItems, ...records];
  }, [q, pages, hits]);

  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const go = (item: Item | undefined) => {
    if (!item) return;
    setOpen(false);
    change("");
    if (item.external) window.open(item.href, "_blank", "noopener,noreferrer");
    else router.push(item.href);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((i) => Math.min(i + 1, items.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); go(items[active]); }
  };

  const searching = q.trim().length >= 2 && (pending || hits.q !== q.trim());
  let lastSection = "";

  return (
    <D.Root open={open} onOpenChange={(o) => { setOpen(o); if (!o) change(""); }}>
      <D.Trigger className="hidden items-center gap-2 rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-muted hover:border-border-strong hover:text-fg sm:inline-flex">
        <Search className="size-4" />
        <span>Search</span>
        <kbd className="ml-4 rounded border border-border px-1.5 font-mono text-[10.5px] text-faint">⌘K</kbd>
      </D.Trigger>
      <D.Trigger className="inline-flex size-8 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-fg sm:hidden" aria-label="Search">
        <Search className="size-4" />
      </D.Trigger>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px]" />
        <D.Content className="fixed left-1/2 top-[12vh] z-50 w-[min(92vw,640px)] -translate-x-1/2 overflow-hidden rounded-lg border border-border bg-surface shadow-2xl" aria-describedby={undefined}>
          <D.Title className="sr-only">Search blakSOC</D.Title>
          <div className="flex items-center gap-2 border-b border-border px-4">
            <Search className="size-4 shrink-0 text-muted" />
            <input
              autoFocus
              value={q}
              onChange={(e) => change(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder="Search pages, assets, alerts, incidents, CVEs…"
              className="h-12 w-full bg-transparent text-sm outline-none placeholder:text-faint"
              role="combobox"
              aria-expanded
              aria-controls={listId}
              aria-activedescendant={items[active] ? `${listId}-${active}` : undefined}
              aria-autocomplete="list"
            />
            {searching ? <span className="shrink-0 text-[11px] text-faint">Searching…</span> : null}
          </div>
          <div ref={listRef} id={listId} role="listbox" aria-label="Results" className="max-h-[60vh] overflow-y-auto py-1">
            {items.map((item, i) => {
              const header = item.section !== lastSection ? item.section : null;
              lastSection = item.section;
              const Icon = item.icon;
              return (
                <div key={item.key}>
                  {header ? <div className="px-4 pb-1 pt-2.5 text-[10.5px] font-semibold uppercase tracking-[0.12em] text-faint" role="presentation">{header}</div> : null}
                  <div
                    id={`${listId}-${i}`}
                    data-index={i}
                    role="option"
                    aria-selected={i === active}
                    onMouseMove={() => setActive(i)}
                    onClick={() => go(item)}
                    className={cn("mx-1 flex cursor-pointer items-center gap-3 rounded-md px-3 py-2", i === active ? "bg-accent-soft text-fg" : "text-muted")}
                  >
                    <Icon className={cn("size-4 shrink-0", i === active ? "text-accent" : "text-faint")} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm text-fg">{item.title}</span>
                      <span className="block truncate text-[11px] text-faint">{item.detail}</span>
                    </span>
                    {item.external ? <ExternalLink className="size-3.5 shrink-0 text-faint" aria-label="Opens in a new tab" /> : null}
                  </div>
                </div>
              );
            })}
            {!items.length && !searching ? (
              <div className="px-4 py-8 text-center text-sm text-muted">{hits.error ?? `Nothing matches “${q.trim()}”.`}</div>
            ) : null}
          </div>
          <div className="flex items-center gap-4 border-t border-border px-4 py-2 text-[11px] text-faint">
            <span><kbd className="font-mono">↑↓</kbd> move</span>
            <span><kbd className="font-mono">↵</kbd> open</span>
            <span><kbd className="font-mono">esc</kbd> close</span>
            <span className="ml-auto">Searches the selected workspace</span>
          </div>
        </D.Content>
      </D.Portal>
    </D.Root>
  );
}
