import Link from "next/link";
import { HermesBadge } from "@/components/soc/hermes-badge";
import { RefLink, StatusBadge } from "@/components/soc/indicators";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { HistoryEntry } from "@/lib/alerts/history";
import { sourceLabel } from "@/lib/alerts/provenance";
import type { AlertProvenance } from "@/lib/services/alert-provenance";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";

/** "How this alert was created": source, timing, the path from event to alert, and what followed. */
export function ProvenanceCard({ p }: { p: AlertProvenance }) {
  const { where, when, how, next } = p;
  const ruleLink = (label: string) => (where.ruleId ? <RefLink type="rule" id={where.ruleId} label={label} /> : label);
  const sourceFacts: Fact[] = [
    { label: "Source", value: where.source },
    { label: "External ID", value: <span className="font-mono" title={where.externalId}>{where.externalId}</span> },
    // Raw is withheld from customers; the stored rule id still says which rule fired.
    ...(where.ruleId && !where.fields.some((f) => f.label === "Rule") ? [{ label: "Rule", value: ruleLink(where.ruleId) }] : []),
    ...where.fields.map((f) => ({ label: f.label, value: f.label === "Rule" ? ruleLink(f.value) : f.value })),
  ];
  const more = how.factorCount - how.topFactors.length;
  const risk = how.topFactors.length
    ? ` from ${how.topFactors.map((f) => `${f.label} (+${f.points})`).join(", ")}${more > 0 ? ` and ${more} more` : ""}`
    : " (no contributing factors)";
  const ocsf = how.ocsf ? `OCSF ${how.ocsf.finding}${how.ocsf.sourceEvent ? ` + ${how.ocsf.sourceEvent}` : ""}${how.ocsf.version ? ` (${how.ocsf.version})` : ""}` : "No OCSF record stored";
  return (
    <Card>
      <CardHeader>
        <CardTitle>How this alert was created</CardTitle>
        <span className="text-xs text-muted">Source, timing and the steps that made it an alert</span>
      </CardHeader>
      <div className="grid divide-y divide-border md:grid-cols-2 md:divide-y-0 xl:grid-cols-4 xl:divide-x">
        <Section title="Where it came from">
          <p>
            {where.integration ? (
              <>
                Collected by{" "}
                {where.integration.canOpen ? <Link href={`/integrations/${where.integration.id}`} className="text-accent hover:underline">{where.integration.name}</Link> : <span className="font-medium">{where.integration.name}</span>}
                <span className="text-muted"> ({where.integration.provider}{where.integration.shared ? ", shared" : ""}{where.integration.enabled ? "" : ", now disabled"})</span>
              </>
            ) : where.hiddenIntegration ? (
              <>Collected by a shared {sourceLabel(where.source)} integration run by the SOC</>
            ) : (
              <>Raised inside blakSOC ({sourceLabel(where.source)})</>
            )}
          </p>
          <Facts rows={sourceFacts} />
          {where.rawWithheld ? <p className="text-xs text-faint">Source event details are visible to the SOC only.</p> : null}
        </Section>

        <Section title="When">
          <Facts
            rows={[
              { label: "Event time", value: <span title={timeAgo(when.occurredAt)}>{fmtDateTime(when.occurredAt)}</span> },
              { label: "Stored by blakSOC", value: <span title={timeAgo(when.ingestedAt)}>{fmtDateTime(when.ingestedAt)}</span> },
            ]}
          />
          <p className="text-xs text-muted">{capital(when.delay)}.</p>
        </Section>

        <Section title="How it became an alert">
          <p>{how.reason}</p>
          {how.raisedBy?.explanation.length ? (
            <ul className="list-disc space-y-0.5 pl-4 text-xs text-muted">
              {how.raisedBy.explanation.slice(0, 4).map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          ) : null}
          <Facts
            rows={[
              ...(where.integration?.floor ? [{ label: "Alert floor now", value: `${where.integration.floor}; lower events stay in the source` }] : []),
              { label: "Risk", value: <><span className="num font-semibold">{how.riskScore}</span><span className="text-muted">{risk}</span></> },
              { label: "Normalised", value: ocsf },
              { label: "Threat intel", value: intelSentence(how.intel) },
            ]}
          />
        </Section>

        <Section title="What happened next">
          {next.incident ? (
            <div className="space-y-1">
              <p>
                {next.incident.origin === "auto" ? "Grouped automatically into " : "Added to "}
                <Link href={`/soc/incidents/${next.incident.id}`} className="text-accent hover:underline">INC-{next.incident.ref}</Link>
                {next.incident.linkedAt ? <span className="text-muted"> {timeAgo(next.incident.linkedAt)}</span> : null}
                <span className="ml-1.5 inline-block align-middle"><StatusBadge status={next.incident.status} /></span>
              </p>
              <p className="truncate text-xs text-muted" title={next.incident.title}>{next.incident.title}</p>
              {next.incident.reason ? <p className="text-xs text-muted">{next.incident.reason}</p> : null}
              {next.incident.kelpie ? (
                <p className="text-xs">
                  Kelpie case{" "}
                  {next.incident.kelpie.pending ? (
                    <span className="text-muted">not created yet{next.incident.kelpie.lastError ? ` (${next.incident.kelpie.lastError})` : ""}</span>
                  ) : next.incident.kelpie.url ? (
                    <a href={next.incident.kelpie.url} target="_blank" rel="noreferrer" className="text-accent hover:underline">{next.incident.kelpie.caseNumber ?? "open"}</a>
                  ) : (
                    <span className="font-medium">{next.incident.kelpie.caseNumber ?? "linked"}</span>
                  )}
                </p>
              ) : null}
            </div>
          ) : (
            <p className="text-muted">Not part of an incident.</p>
          )}
          {next.contributedTo.length ? (
            <div className="space-y-1">
              <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Fed correlation findings</div>
              <ul className="space-y-0.5 text-xs">
                {next.contributedTo.map((f) => (
                  <li key={f.id}>
                    {f.alertId ? <Link href={`/soc/alerts/${f.alertId}`} className="text-accent hover:underline">{f.rule}</Link> : f.rule}
                    <span className="text-muted" title={fmtDateTime(f.at)}> · {timeAgo(f.at)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </Section>
      </div>
    </Card>
  );
}

function intelSentence(i: AlertProvenance["how"]["intel"]): string {
  if (i.verdict === "unchecked" && !i.checkedAt) return "Not checked (no intel source connected at ingest)";
  const when = i.checkedAt ? ` ${fmtDateTime(i.checkedAt)}` : "";
  if (!i.matches) return `Checked${when}; no matches`;
  return `Checked${when}; ${i.matches} match${i.matches === 1 ? "" : "es"}, verdict ${i.verdict}`;
}

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="min-w-0 space-y-2 px-4 py-3 text-sm" aria-label={title}>
      <h4 className="text-[11px] font-semibold uppercase tracking-[0.12em] text-faint">{title}</h4>
      {children}
    </section>
  );
}

type Fact = { label: string; value: React.ReactNode };

function Facts({ rows }: { rows: Fact[] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
      {rows.map(({ label, value }, i) => (
        <div key={`${i}:${label}`} className="contents">
          <dt className="text-faint">{label}</dt>
          <dd className="min-w-0 break-words">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Every recorded change to the alert, oldest first, starting with its creation. */
export function HistoryCard({ entries, truncated }: { entries: HistoryEntry[]; truncated: boolean }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>History</CardTitle>
        <span className="text-xs text-muted">From the audit log</span>
      </CardHeader>
      <CardContent>
        <ol className="relative space-y-3 border-l border-border pl-4">
          {entries.map((e) => (
            <li key={e.key} className="relative text-sm">
              <span aria-hidden className={cn("absolute -left-[21px] top-1.5 size-2 rounded-full", e.hermes ? "bg-hermes" : "bg-border")} />
              <div>{e.href ? <Link href={e.href} className="hover:text-accent">{e.text}</Link> : e.text}</div>
              <div className="flex flex-wrap items-center gap-1 text-xs text-muted">
                {e.hermes ? <HermesBadge size="sm" /> : e.actor} · <span title={fmtDateTime(e.at)}>{timeAgo(e.at)}</span>
              </div>
            </li>
          ))}
        </ol>
        {truncated ? <p className="mt-3 text-xs text-faint">Showing the first 200 entries.</p> : null}
      </CardContent>
    </Card>
  );
}
