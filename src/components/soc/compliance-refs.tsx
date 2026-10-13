import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { e8Label, ismText } from "@/lib/compliance/refs";
import { ISM_RELEASE } from "@/lib/compliance/ism-catalogue";

/** ISM and Essential Eight references a detector mapped this alert to. Renders nothing when there are none. */
export function ComplianceRefsCard({ ism, e8, source }: { ism: string[]; e8: string[]; source: string }) {
  if (!ism.length && !e8.length) return null;
  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-baseline justify-between gap-2">
        <CardTitle>Compliance references</CardTitle>
        <span className="text-xs text-muted">Mapped by {source === "wedgetail" ? "Wedgetail" : source} · evidence for these controls, not an assessment</span>
      </CardHeader>
      <CardContent className="grid gap-5 lg:grid-cols-[1fr_2fr]">
        <div>
          <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">Essential Eight</h3>
          {e8.length ? (
            <ul className="mt-2 flex flex-wrap gap-1.5">
              {e8.map((id) => <li key={id}><Link href={`/soc/compliance#e8-${id}`} className="inline-flex rounded border border-border px-2 py-0.5 text-xs hover:border-accent hover:text-accent">{e8Label(id)}</Link></li>)}
            </ul>
          ) : <p className="mt-2 text-xs text-faint">None mapped</p>}
        </div>
        <div>
          <h3 className="text-[11px] font-medium uppercase tracking-wider text-faint">ISM controls</h3>
          {ism.length ? (
            <ul className="mt-2 space-y-2">
              {ism.map((id) => (
                <li key={id} className="grid grid-cols-[5.5rem_1fr] gap-2 text-xs">
                  <Link href={`/soc/compliance#${id}`} className="font-mono text-accent hover:underline">{id}</Link>
                  <span className="text-muted">{ismText(id) ?? "Not in the bundled ISM snapshot."}</span>
                </li>
              ))}
            </ul>
          ) : <p className="mt-2 text-xs text-faint">None mapped</p>}
          {ism.length ? <p className="mt-3 text-[11px] text-faint">ISM {ISM_RELEASE.version} control text © Commonwealth of Australia, CC BY 4.0.</p> : null}
        </div>
      </CardContent>
    </Card>
  );
}
