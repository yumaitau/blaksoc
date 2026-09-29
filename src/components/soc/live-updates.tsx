"use client";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

type Evt = { type: string; title?: string; summary?: string; severity?: string };

/** Subscribes to /api/stream and refreshes server components (throttled) when SOC events arrive. */
export function LiveUpdates() {
  const router = useRouter();
  const [connected, setConnected] = useState(false);
  const [last, setLast] = useState<Evt | null>(null);
  const pending = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const es = new EventSource("/api/stream");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener("soc", (m) => {
      const e = JSON.parse((m as MessageEvent).data) as Evt;
      setLast(e);
      if (!pending.current) {
        pending.current = setTimeout(() => {
          pending.current = null;
          router.refresh();
        }, 1500);
      }
    });
    return () => {
      es.close();
      if (pending.current) clearTimeout(pending.current);
    };
  }, [router]);

  return (
    <div className="flex shrink-0 items-center gap-2 text-xs text-muted" aria-live="polite">
      {last ? <span className="hidden max-w-80 truncate lg:inline">{last.type.replace(".", " ")}: {last.title ?? last.summary ?? ""}</span> : null}
      <span className={cn("inline-flex items-center gap-1.5 rounded-full border border-border px-2 py-0.5", connected ? "text-ok" : "text-faint")}>
        <span className={cn("size-1.5 rounded-full", connected ? "animate-pulse bg-ok" : "bg-faint")} />
        {connected ? "Live" : "Offline"}
      </span>
    </div>
  );
}
