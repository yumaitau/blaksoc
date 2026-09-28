import { Badge } from "@/components/ui/badge";
import type { integrationAudit, listIntegrations } from "@/lib/services/integrations";
import { fmtDateTime } from "@/lib/utils";

export type IntegrationRow = Awaited<ReturnType<typeof listIntegrations>>[number];
type AuditRow = Awaited<ReturnType<typeof integrationAudit>>[number];

export function ConnectionStatus({ status, enabled }: { status: string; enabled: boolean }) {
  if (!enabled) return <Badge variant="outline">Disabled</Badge>;
  if (status === "healthy") return <Badge variant="ok">Healthy</Badge>;
  if (status === "error") return <Badge variant="danger">Error</Badge>;
  if (status === "degraded") return <Badge variant="warn">Degraded</Badge>;
  return <Badge>Not tested</Badge>;
}

function short(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "string") return v;
  const s = JSON.stringify(v);
  return s.length > 80 ? `${s.slice(0, 77)}…` : s;
}

/** Key/value rendering for non-secret config and health. Secrets are never selected by the service. */
export function KeyValues({ data, empty = "None" }: { data: Record<string, unknown> | null | undefined; empty?: string }) {
  const entries = data ? Object.entries(data) : [];
  if (!entries.length) return <span className="text-xs text-faint">{empty}</span>;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-faint">{k}</dt>
          <dd className="min-w-0 truncate font-mono" title={typeof v === "string" ? v : JSON.stringify(v)}>{short(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function AuditHistory({ rows }: { rows: AuditRow[] }) {
  if (!rows.length) return <p className="text-xs text-faint">No audit entries.</p>;
  return (
    <ol className="space-y-1.5">
      {rows.map((r) => (
        <li key={r.id} className="text-xs">
          <span className="font-medium">{r.action.replace("integration.", "")}</span>
          <span className="text-muted"> · {r.actorKind} · {fmtDateTime(r.at)}</span>
          {r.detail ? <div className="truncate font-mono text-[11px] text-faint" title={JSON.stringify(r.detail)}>{JSON.stringify(r.detail)}</div> : null}
        </li>
      ))}
    </ol>
  );
}
