import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { IntelVerdict, PageHeader, RiskScore, SeverityBadge, StatusBadge } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { getAsset } from "@/lib/services/assets";
import { cn, fmtDateTime, timeAgo } from "@/lib/utils";
import { AgentStatus, Criticality, Exposure } from "../asset-bits";
import { EditAsset } from "./edit-asset";

export const metadata = { title: "Asset" };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 text-sm">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 text-right">{children}</dd>
    </div>
  );
}

function Section({ title, count, children, action }: { title: string; count?: number; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}{count != null ? <span className="num ml-2 text-muted">{count}</span> : null}</CardTitle>
        {action}
      </CardHeader>
      {children}
    </Card>
  );
}

const None = ({ children }: { children: React.ReactNode }) => <div className="p-4 text-sm text-muted">{children}</div>;

/** Everything known about one asset, with the integrations it was merged from. */
export default async function AssetPage({ params }: { params: Promise<{ id: string }> }) {
  const ctx = await requireAccess();
  if (!can(ctx, "asset:read")) redirect("/portal");
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const d = await getAsset(ctx, id);
  if (!d) notFound();
  const a = d.asset;
  const canWrite = can(ctx, "asset:write", a.tenantId);
  const openVulns = d.vulnerabilities.filter((v) => v.status === "open");
  const openAlerts = d.alerts.filter((x) => x.status !== "RESOLVED" && x.status !== "FALSE_POSITIVE");
  const alertHref = (alertId: string) => (ctx.isPlatform ? `/soc/alerts/${alertId}` : null);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={`Asset · ${a.kind.replaceAll("_", " ")}`}
        title={a.name}
        description={[d.tenantName, a.hostname && a.hostname !== a.name ? a.hostname : null, a.os].filter(Boolean).join(" · ")}
        actions={<Link href="/assets" className="text-sm text-accent hover:underline">← All assets</Link>}
      />

      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card><CardContent className="py-3"><div className="text-[11px] uppercase tracking-wider text-faint">Risk</div><div className="mt-1"><RiskScore score={a.riskScore} /></div></CardContent></Card>
        <Card><CardContent className="py-3"><div className="text-[11px] uppercase tracking-wider text-faint">Open alerts</div><div className={cn("num mt-1 text-2xl font-semibold", openAlerts.length && "text-sev-high")}>{openAlerts.length}</div></CardContent></Card>
        <Card><CardContent className="py-3"><div className="text-[11px] uppercase tracking-wider text-faint">Open vulnerabilities</div><div className={cn("num mt-1 text-2xl font-semibold", openVulns.some((v) => v.priorityScore >= 70) && "text-sev-critical")}>{openVulns.length}</div></CardContent></Card>
        <Card><CardContent className="py-3"><div className="text-[11px] uppercase tracking-wider text-faint">Incidents</div><div className="num mt-1 text-2xl font-semibold">{d.incidents.length}</div></CardContent></Card>
      </section>

      <Section title="Backup">
        {d.backup ? (
          <dl className="grid gap-x-8 px-4 py-2 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="Last success">{d.backup.lastSuccessAt ? fmtDateTime(d.backup.lastSuccessAt) : "none"}</Field>
            <Field label="Failed jobs">{d.backup.failedJobs}</Field>
            <Field label="Restore test">{d.backup.restoreTestedAt ? fmtDateTime(d.backup.restoreTestedAt) : "not recorded"}</Field>
            <Field label="Immutable copy">{d.backup.immutable ? "yes" : "no"}</Field>
            <Field label="Offline copy">{d.backup.offlineCopy ? "yes" : "no"}</Field>
            {d.backup.stale ? <Field label="Status"><Badge variant="danger">stale</Badge></Field> : null}
          </dl>
        ) : <None>No backup status for this asset.</None>}
      </Section>

      <div className="grid gap-5 xl:grid-cols-3">
        {/* Context */}
        <div className="space-y-5">
          <Card>
            <CardHeader><CardTitle>Context</CardTitle></CardHeader>
            <CardContent className="py-2">
              <dl className="divide-y divide-border">
                <Field label="Customer">{d.tenantName}</Field>
                <Field label="Owner">{a.owner ?? <span className="text-faint">unassigned</span>}</Field>
                <Field label="Criticality"><Criticality value={a.criticality} /></Field>
                <Field label="Exposure"><Exposure value={a.exposure} /></Field>
                {a.kind === "identity" ? <Field label="Privileged">{a.privileged ? <Badge variant="danger">privileged</Badge> : "no"}</Field> : <Field label="Agent"><AgentStatus status={a.agentStatus} /></Field>}
                <Field label="IP addresses"><span className="font-mono text-xs">{a.ips.join(", ") || "—"}</span></Field>
                <Field label="Tags">{a.tags.length ? <span className="inline-flex flex-wrap justify-end gap-1">{a.tags.map((t) => <Badge key={t} variant="outline">{t}</Badge>)}</span> : "—"}</Field>
                <Field label="First seen">{fmtDateTime(a.firstSeen)}</Field>
                <Field label="Last seen">{fmtDateTime(a.lastSeen)}</Field>
              </dl>
            </CardContent>
          </Card>

          {canWrite ? (
            <Card>
              <CardHeader><CardTitle>Business context</CardTitle></CardHeader>
              <CardContent>
                <EditAsset id={a.id} criticality={a.criticality} exposure={a.exposure} owner={a.owner} privileged={a.privileged} isIdentity={a.kind === "identity"} />
              </CardContent>
            </Card>
          ) : null}

          <Section title="Sources" count={d.sources.length}>
            {d.sources.length === 0 ? <None>Added manually; not linked to an integration.</None> : (
              <div className="divide-y divide-border">
                {d.sources.map((s, i) => (
                  <div key={i} className="px-4 py-2">
                    <div className="flex items-center justify-between gap-2 text-sm">
                      <span className="truncate font-medium">{s.integration ?? "Removed integration"}</span>
                      {s.provider ? <Badge variant="outline">{s.provider}</Badge> : null}
                    </div>
                    <div className="truncate text-[11px] text-muted"><span className="font-mono">{s.externalId}</span> · synced {timeAgo(s.lastSyncedAt)}</div>
                  </div>
                ))}
                {d.sources.length > 1 ? <div className="px-4 py-2 text-xs text-muted">Deduplicated from {d.sources.length} integrations into one record.</div> : null}
              </div>
            )}
          </Section>
        </div>

        <div className="space-y-5 xl:col-span-2">
          <Section title="Vulnerabilities" count={openVulns.length} action={<Link href="/vulnerabilities" className="text-xs text-accent hover:underline">Patch priorities →</Link>}>
            {d.vulnerabilities.length === 0 ? <None>No known vulnerabilities.</None> : (
              <Table>
                <THead>
                  <tr className="border-b border-border"><TH>Priority</TH><TH>CVE</TH><TH>Package</TH><TH>Fixed in</TH><TH>Status</TH></tr>
                </THead>
                <TBody>
                  {d.vulnerabilities.map((v) => (
                    <TR key={v.id}>
                      <TD><RiskScore score={v.priorityScore} factors={v.priorityFactors} /></TD>
                      <TD>
                        <Link href={`/vulnerabilities?cve=${v.cve}&tenant=${a.tenantId}`} className="font-mono text-xs font-medium hover:text-accent">{v.cve}</Link>
                        {v.title ? <div className="max-w-72 truncate text-[11px] text-muted">{v.title}</div> : null}
                      </TD>
                      <TD className="font-mono text-xs">{v.packageName ?? "—"} {v.packageVersion}</TD>
                      <TD className="font-mono text-xs text-muted">{v.fixedVersion ?? "—"}</TD>
                      <TD><Badge variant={v.status === "open" ? "warn" : v.status === "patched" ? "ok" : "default"}>{v.status}</Badge></TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Section>

          <div className="grid gap-5 lg:grid-cols-2">
            <Section title="Alerts" count={d.alerts.length}>
              {d.alerts.length === 0 ? <None>No alerts on this asset.</None> : (
                <div className="divide-y divide-border">
                  {d.alerts.slice(0, 15).map((x) => {
                    const body = (
                      <>
                        <SeverityBadge severity={x.severity} />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm">{x.title}</div>
                          <div className="truncate text-[11px] text-muted">{timeAgo(x.occurredAt)}{x.userName ? ` · ${x.userName}` : ""}</div>
                        </div>
                        <StatusBadge status={x.status} />
                      </>
                    );
                    const href = alertHref(x.id);
                    return href ? <Link key={x.id} href={href} className="flex items-center gap-3 px-4 py-2 hover:bg-surface-2/60">{body}</Link> : <div key={x.id} className="flex items-center gap-3 px-4 py-2">{body}</div>;
                  })}
                </div>
              )}
            </Section>

            <Section title="Incidents" count={d.incidents.length}>
              {d.incidents.length === 0 ? <None>Not linked to any incident.</None> : (
                <div className="divide-y divide-border">
                  {d.incidents.map((i) => (
                    <Link key={i.id} href={`/soc/incidents/${i.id}`} className="flex items-center gap-3 px-4 py-2 hover:bg-surface-2/60">
                      <span className="num font-mono text-xs text-faint">INC-{i.ref}</span>
                      <SeverityBadge severity={i.severity} />
                      <span className="min-w-0 flex-1 truncate text-sm">{i.title}</span>
                      <StatusBadge status={i.status} />
                    </Link>
                  ))}
                </div>
              )}
            </Section>

            <Section title="Threat-intel sightings" count={d.sightings.length}>
              {d.sightings.length === 0 ? <None>No OpenCTI matches from activity on this asset.</None> : (
                <div className="divide-y divide-border">
                  {d.sightings.map((m) => {
                    const body = (
                      <>
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-mono text-xs">{m.summary.observable.value}</span>
                          <IntelVerdict verdict={m.verdict} />
                        </div>
                        <div className="truncate text-[11px] text-muted">
                          {[...m.summary.malware, ...m.summary.intrusionSets, ...m.summary.threatActors].slice(0, 3).join(", ") || m.summary.source || "OpenCTI"} · {timeAgo(m.matchedAt)}
                        </div>
                      </>
                    );
                    return ctx.isPlatform ? (
                      <Link key={m.id} href={`/intel?q=${encodeURIComponent(m.summary.observable.value)}`} className="block px-4 py-2 hover:bg-surface-2/60">{body}</Link>
                    ) : (
                      <div key={m.id} className="px-4 py-2">{body}</div>
                    );
                  })}
                </div>
              )}
            </Section>

            <Section title="Identities" count={d.identities.length}>
              {d.identities.length === 0 ? <None>No user activity recorded on this asset.</None> : (
                <div className="flex flex-wrap gap-1.5 p-4">
                  {d.identities.map((u) => (
                    <Link key={u} href={`/assets?kind=identity&q=${encodeURIComponent(u)}`} className="rounded border border-border px-1.5 py-0.5 font-mono text-xs hover:border-accent hover:text-accent">{u}</Link>
                  ))}
                </div>
              )}
            </Section>
          </div>

          <Section title="Software" count={a.software.length}>
            {a.software.length === 0 ? <None>No software inventory reported.</None> : (
              <div className="grid gap-x-6 px-4 py-2 sm:grid-cols-2">
                {a.software.map((s, i) => (
                  <div key={i} className="flex justify-between gap-3 border-b border-border py-1.5 text-sm last:border-0">
                    <span className="truncate">{s.name}</span>
                    <span className="font-mono text-xs text-muted">{s.version}</span>
                  </div>
                ))}
              </div>
            )}
          </Section>
        </div>
      </div>
    </div>
  );
}
