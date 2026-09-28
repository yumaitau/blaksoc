import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export const ASSET_KINDS = ["endpoint", "server", "identity", "cloud_resource", "application", "domain", "ip", "network_device", "saas"] as const;
export const EXPOSURES = ["internet", "internal", "isolated"] as const;

/** 1–5 pips; 4+ is a critical asset. */
export function Criticality({ value }: { value: number }) {
  return (
    <span className="inline-flex items-center gap-1.5" title={`Criticality ${value} of 5`}>
      <span className="inline-flex gap-0.5" aria-hidden>
        {[1, 2, 3, 4, 5].map((i) => (
          <span key={i} className={cn("h-2.5 w-1 rounded-sm", i <= value ? (value >= 4 ? "bg-sev-high" : "bg-accent") : "bg-surface-2")} />
        ))}
      </span>
      <span className="num text-xs text-muted">{value}<span className="sr-only"> of 5</span></span>
    </span>
  );
}

export function Exposure({ value }: { value: string }) {
  if (value === "internet") return <Badge variant="danger">internet</Badge>;
  if (value === "isolated") return <Badge variant="ok">isolated</Badge>;
  return <Badge variant="outline">{value}</Badge>;
}

export function AgentStatus({ status }: { status: string | null }) {
  if (!status) return <span className="text-xs text-faint">no agent</span>;
  const ok = status === "active";
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs", ok ? "text-ok" : "text-warn")}>
      <span className={cn("size-1.5 rounded-full", ok ? "bg-ok" : "bg-warn")} />
      {ok ? "online" : status.replaceAll("_", " ")}
    </span>
  );
}
