import { PageHeader } from "@/components/soc/indicators";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { TenantTrends } from "@/lib/services/trends";

function minutes(value: number | null, empty: string) {
  if (value == null) return empty;
  const rounded = Math.round(value);
  if (Math.abs(rounded) < 60) return `${rounded} min`;
  const sign = rounded < 0 ? "-" : "";
  const abs = Math.abs(rounded);
  return `${sign}${Math.floor(abs / 60)} h ${abs % 60} min`;
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-border bg-surface px-3 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-faint">{label}</div>
      <div className="mt-1 break-words text-lg font-semibold">{value}</div>
      {hint ? <div className="mt-0.5 text-xs text-muted">{hint}</div> : null}
    </div>
  );
}

/** Summary stays on screen at phone width. The daily bars are desktop only. */
export function TrendSummary({ data, eyebrow, title, description }: { data: TenantTrends; eyebrow: string; title: string; description: string }) {
  const total = data.volume.reduce((sum, row) => sum + row.count, 0);
  const max = data.volume.reduce((peak, row) => Math.max(peak, row.count), 1);
  return (
    <div className="space-y-5">
      <PageHeader eyebrow={eyebrow} title={title} description={description} />
      <section className="grid grid-cols-2 gap-3">
        <Stat label="Alerts" value={String(total)} hint={`Last ${data.days} days`} />
        <Stat label="Seats" value={String(data.seats)} hint="Endpoints and servers" />
        <Stat label="Agents active" value={String(data.agents.active)} />
        <Stat label="Agents offline" value={String(data.agents.offline)} />
        <Stat label="Agents unknown" value={String(data.agents.unknown)} hint="No agent status reported" />
        <Stat label="Time to open" value={minutes(data.mttaMinutes, "No linked alerts")} hint="Alert time to incident record" />
        <Stat label="Time to close" value={minutes(data.mttrMinutes, "No closed incidents")} hint="Incident open to close" />
      </section>
      <section className="grid gap-3 sm:grid-cols-2">
        <Card className="min-w-0">
          <CardHeader><CardTitle>Top detections</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {data.topDetections.length === 0 ? <p className="text-sm text-muted">No detections in this window.</p> : data.topDetections.map((row) => (
              <div key={row.ruleId} className="flex items-baseline justify-between gap-3 text-sm">
                <span className="min-w-0 break-all">{row.ruleId}</span>
                <span className="num shrink-0">{row.count}</span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card className="min-w-0">
          <CardHeader><CardTitle>Noisy assets</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {data.noisyAssets.length === 0 ? <p className="text-sm text-muted">No asset on these alerts.</p> : data.noisyAssets.map((row) => (
              <div key={row.assetId} className="flex items-baseline justify-between gap-3 text-sm">
                <span className="min-w-0 break-words">{row.name}</span>
                <span className="num shrink-0">{row.count}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </section>
      <section className="hidden sm:block">
        <Card>
          <CardHeader><CardTitle>Alerts per day</CardTitle></CardHeader>
          <CardContent className="space-y-1">
            {data.volume.map((row) => (
              <div key={row.day} className="flex items-center gap-2">
                <span className="w-12 shrink-0 text-[10px] text-faint">{row.day.slice(5)}</span>
                <span className="h-2 min-w-0 flex-1 overflow-hidden rounded bg-surface-2">
                  <span className="block h-full bg-accent" style={{ width: `${Math.round((row.count / max) * 100)}%` }} />
                </span>
                <span className="num w-10 shrink-0 text-right text-[10px]">{row.count}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
