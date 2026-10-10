import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { RadarOutage, RadarSection, RadarShare } from "@/lib/radar/snapshot";
import { fmtDateTime } from "@/lib/utils";

const SETUP = "https://developers.cloudflare.com/radar/get-started/first-request/";

export function RadarPending({ title }: { title: string }) {
  return (
    <Card className="h-full">
      <CardHeader><CardTitle>{title}</CardTitle></CardHeader>
      <CardContent className="text-sm text-muted">Shown when CLOUDFLARE_RADAR_TOKEN is set. Account &gt; Radar &gt; Read.</CardContent>
    </Card>
  );
}

export function RadarSetup() {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Cloudflare Radar</CardTitle>
        <a href={SETUP} target="_blank" rel="noreferrer" className="text-xs text-accent hover:underline">Create a token</a>
      </CardHeader>
      <CardContent className="space-y-2 text-sm text-muted">
        <p>Application attacks, network attacks, outages and bot traffic for Australia. This is Cloudflare&apos;s view of the internet, not a customer&apos;s logs.</p>
        <p>Set <span className="font-mono text-xs text-fg">CLOUDFLARE_RADAR_TOKEN</span> to an API token with Account &gt; Radar &gt; Read.</p>
      </CardContent>
    </Card>
  );
}

function Bars({ rows }: { rows: RadarShare[] }) {
  const max = Math.max(...rows.map((row) => row.pct), 0.0001);
  return (
    <div className="space-y-2">
      {rows.map((row) => (
        <div key={row.key}>
          <div className="flex justify-between gap-2 text-xs">
            <span className="truncate">{row.label}</span>
            <span className="num text-muted">{row.pct.toFixed(1)}%</span>
          </div>
          <div className="mt-1 h-1 rounded-full bg-surface-2">
            <div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(2, (row.pct / max) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function RadarShareCard({ title, hint, href, section }: { title: string; hint: string; href: string; section: RadarSection<RadarShare> }) {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <a href={href} target="_blank" rel="noreferrer" className="text-xs text-accent hover:underline">Radar</a>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-[11px] text-muted">{hint}</p>
        {section.error ? <p className="text-sm text-danger">{section.error}</p> : section.rows.length === 0 ? <p className="text-sm text-muted">No data in this window.</p> : <Bars rows={section.rows} />}
      </CardContent>
    </Card>
  );
}

export function RadarOutageCard({ section }: { section: RadarSection<RadarOutage> }) {
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Internet outages</CardTitle>
        <a href="https://radar.cloudflare.com/outage-center" target="_blank" rel="noreferrer" className="text-xs text-accent hover:underline">Radar</a>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-[11px] text-muted">Australia · last 7 days · Cloudflare Radar. Not a customer&apos;s network.</p>
        {section.error ? <p className="text-sm text-danger">{section.error}</p> : section.rows.length === 0 ? <p className="text-sm text-muted">No outages recorded in this window.</p> : (
          <ul className="divide-y divide-border">
            {section.rows.map((row) => (
              <li key={row.id} className="py-2">
                <div className="text-sm">{row.scope || row.cause || "Outage"}</div>
                <div className="mt-0.5 text-[11px] text-muted">
                  {[row.locations, row.cause, row.start ? fmtDateTime(row.start) : ""].filter(Boolean).join(" · ")}
                  {row.end ? "" : row.start ? " · ongoing" : ""}
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
