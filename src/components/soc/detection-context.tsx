import Link from "next/link";
import { ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/soc/indicators";
import { explainDetection, type DetectionAlert } from "@/lib/incidents/explanation";
import { fmtDateTime } from "@/lib/utils";

export function WazuhAlertButton({ url }: { url: string }) {
  return <Button asChild size="sm" variant="secondary"><a href={url} target="_blank" rel="noopener noreferrer"><ExternalLink /> Open Wazuh alert</a></Button>;
}

export function DetectionContext({ alerts }: { alerts: DetectionAlert[] }) {
  return <Card>
    <CardHeader><CardTitle>Why this needs attention</CardTitle></CardHeader>
    <CardContent className="space-y-5">
      {alerts.length === 0 ? <p className="text-sm text-muted">No source alerts are linked. Review the case description and timeline to establish why this incident was opened.</p> : null}
      {alerts.map((a, i) => i === 0 ? <Detection key={a.id} alert={a} /> : (
        <details key={a.id} className="border-t border-border pt-3">
          <summary className="cursor-pointer text-sm font-medium">{a.title}</summary>
          <div className="mt-3"><Detection alert={a} /></div>
        </details>
      ))}
    </CardContent>
  </Card>;
}

function Detection({ alert: a }: { alert: DetectionAlert }) {
  const e = explainDetection(a);
  return <section className="space-y-3" aria-label={a.title}>
    <p className="max-w-prose break-words text-sm font-medium">{e.trigger}</p>
    <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
      <SeverityBadge severity={a.severity} />
      <span>{a.source === "blaksoc-correlation" ? "blakSOC correlation priority" : "Alert severity"}</span>
      {a.source === "wazuh" && a.siemSeverity != null ? <span>· Wazuh rule level {a.siemSeverity}/15</span> : null}
      <span>· {fmtDateTime(a.occurredAt)}</span>
      {a.userName ? <span>· Account: {a.userName}</span> : null}
    </div>
    <p className="max-w-prose text-sm text-muted">{e.meaning}</p>
    {e.fields.length ? <dl className="grid gap-x-5 gap-y-2 text-sm sm:grid-cols-2">{e.fields.map((f) => <div key={f.label}>
      <dt className="text-xs text-faint">{f.label}</dt><dd className="break-words">{f.value}</dd>
    </div>)}</dl> : null}
    {a.groupReason ? <p className="max-w-prose text-xs text-muted"><span className="font-medium text-fg">Why grouped:</span> {a.groupReason.summary}</p> : null}
    <p className="max-w-prose text-sm"><span className="font-medium">Check next:</span> {e.nextStep}</p>
    <div className="flex flex-wrap items-center gap-2">
      {a.wazuhUrl ? <WazuhAlertButton url={a.wazuhUrl} /> : a.source === "wazuh" ? <span className="text-xs text-muted">Wazuh dashboard link is not configured. The event details are available below.</span> : null}
      <Button asChild size="sm" variant="ghost"><Link href={`/soc/alerts/${a.id}`}>View alert details</Link></Button>
    </div>
    {e.evidence ? <details className="text-sm">
      <summary className="cursor-pointer text-muted">{a.source === "blaksoc-correlation" ? "Correlation evidence" : "Original event excerpt"}</summary>
      <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-surface-2 p-3 font-mono text-xs">{e.evidence}</pre>
    </details> : null}
    {a.contributing?.length ? <div className="space-y-2 border-t border-border pt-3">
      <h3 className="text-sm font-medium">Contributing alerts</h3>
      <p className="text-xs text-muted">These are the source events used by the correlation rule. Each keeps its own severity.</p>
      {a.contributing.map((source) => <details key={source.id} className="py-1">
        <summary className="cursor-pointer text-sm">{source.title} <span className="text-xs text-muted">({source.severity}{source.siemSeverity != null ? `, Wazuh level ${source.siemSeverity}` : ""})</span></summary>
        <div className="mt-3"><Detection alert={source} /></div>
      </details>)}
    </div> : a.source === "blaksoc-correlation" ? <p className="text-xs text-muted">Source events could not be loaded. Review the recorded correlation evidence above.</p> : null}
  </section>;
}
