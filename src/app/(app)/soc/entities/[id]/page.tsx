import { ArrowLeft, ArrowRight } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { PageHeader, RefLink } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import type { GraphNode } from "@/lib/graph/traverse";
import { getEntity, type EntityEdgeView } from "@/lib/services/entities";
import { fmtDateTime, timeAgo } from "@/lib/utils";

export const metadata = { title: "Entity" };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const label = (s: string) => s.replaceAll("_", " ");

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 text-sm">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-all text-right">{children}</dd>
    </div>
  );
}

function Provenance({ value }: { value: string }) {
  return value === "observed"
    ? <Badge variant="outline" title="A record states this relationship">observed</Badge>
    : <Badge variant="warn" title="Derived by blakSOC (name match or co-occurrence), not stated by a record">inferred</Badge>;
}

function Evidence({ e }: { e: EntityEdgeView }) {
  if (e.evidenceAlertId) return <RefLink type="alert" id={e.evidenceAlertId} label={e.evidenceType === "intel_match" ? "intel match" : "alert"} />;
  if (e.evidenceType === "asset") return <RefLink type="asset" id={e.evidenceId} label="inventory" />;
  return <span className="text-faint">{label(e.evidenceType)}</span>;
}

/** One entity: what identifies it, what it is directly related to and why, and what is reachable. */
export default async function EntityPage({ params }: { params: Promise<{ id: string }> }) {
  const ctx = await requireAccess();
  if (!can(ctx, "alert:read")) redirect("/portal");
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const d = await getEntity(ctx, id);
  if (!d) notFound();
  const e = d.entity;
  const ids = e.identifiers;
  const byId = new Map(d.neighbours.map((n) => [n.id, n]));

  const groups = new Map<string, EntityEdgeView[]>();
  for (const edge of d.edges) groups.set(edge.type, [...(groups.get(edge.type) ?? []), edge]);
  const reachByType = new Map<string, GraphNode[]>();
  for (const n of d.reach) reachByType.set(n.type, [...(reachByType.get(n.type) ?? []), n]);

  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow={`Entity · ${label(e.type)}`}
        title={e.displayName}
        description={[d.tenantName, e.key !== e.displayName ? e.key : null].filter(Boolean).join(" · ")}
        actions={
          <>
            {typeof ids.alertId === "string" ? <Link href={`/soc/alerts/${ids.alertId}`} className="text-sm text-accent hover:underline">Open alert →</Link> : null}
            {typeof ids.assetId === "string" ? <Link href={`/assets/${ids.assetId}`} className="text-sm text-accent hover:underline">Open asset →</Link> : null}
          </>
        }
      />

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="space-y-5">
          <Card>
            <CardHeader><CardTitle>Identifiers</CardTitle></CardHeader>
            <CardContent className="py-2">
              <dl className="divide-y divide-border">
                <Field label="Key"><span className="font-mono text-xs">{e.key}</span></Field>
                {Object.entries(ids).map(([k, v]) => (
                  <Field key={k} label={k}><span className="font-mono text-xs">{typeof v === "string" || typeof v === "number" ? v : JSON.stringify(v)}</span></Field>
                ))}
                <Field label="Sources">
                  <span className="inline-flex flex-wrap justify-end gap-1">{e.sourceSystems.map((s) => <Badge key={s} variant="outline">{s}</Badge>)}</span>
                </Field>
                <Field label="First seen">{fmtDateTime(e.firstSeen)}</Field>
                <Field label="Last seen">{fmtDateTime(e.lastSeen)}</Field>
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Aliases<span className="num ml-2 text-muted">{d.aliases.length}</span></CardTitle></CardHeader>
            {d.aliases.length === 0 ? <div className="p-4 text-sm text-muted">No alternate identifiers.</div> : (
              <div className="divide-y divide-border">
                {d.aliases.map((a) => (
                  <div key={a.id} className="flex items-center justify-between gap-3 px-4 py-2 text-sm">
                    <span className="min-w-0 truncate font-mono text-xs" title={a.value}>{a.value}</span>
                    <span className="shrink-0 text-[11px] text-muted">{label(a.kind)} · {a.source}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Within 3 hops<span className="num ml-2 text-muted">{d.reach.length}{d.reachTruncated ? "+" : ""}</span></CardTitle>
            </CardHeader>
            {d.reach.length === 0 ? <div className="p-4 text-sm text-muted">Nothing reachable.</div> : (
              <div className="divide-y divide-border">
                {[...reachByType].map(([type, nodes]) => (
                  <div key={type} className="px-4 py-2">
                    <div className="text-[11px] font-medium uppercase tracking-wider text-faint">{label(type)} <span className="num">{nodes.length}</span></div>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {nodes.slice(0, 8).map((n) => (
                        <Link key={n.id} href={`/soc/entities/${n.id}`} title={`${n.depth} hop${n.depth > 1 ? "s" : ""}`} className="max-w-full truncate rounded border border-border px-1.5 py-0.5 text-xs hover:border-accent hover:text-accent">{n.displayName}</Link>
                      ))}
                      {nodes.length > 8 ? <span className="text-xs text-faint">+{nodes.length - 8}</span> : null}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

        <div className="space-y-5 xl:col-span-2">
          {groups.size === 0 ? (
            <Card><CardContent><p className="text-sm text-muted">No relationships recorded.</p></CardContent></Card>
          ) : [...groups].map(([type, edges]) => (
            <Card key={type}>
              <CardHeader><CardTitle>{label(type)}<span className="num ml-2 text-muted">{edges.length}</span></CardTitle></CardHeader>
              <div className="divide-y divide-border">
                {edges.map((edge) => {
                  const outgoing = edge.fromEntityId === e.id;
                  const other = byId.get(outgoing ? edge.toEntityId : edge.fromEntityId);
                  if (!other) return null;
                  return (
                    <div key={edge.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-sm">
                      {outgoing ? <ArrowRight className="size-3.5 shrink-0 text-faint" aria-label="to" /> : <ArrowLeft className="size-3.5 shrink-0 text-faint" aria-label="from" />}
                      <Badge variant="default">{label(other.type)}</Badge>
                      <Link href={`/soc/entities/${other.id}`} className="min-w-0 flex-1 truncate hover:text-accent">{other.displayName}</Link>
                      <Provenance value={edge.provenance} />
                      <span className="num text-xs text-muted" title="Distinct records asserting this relationship">×{edge.count}</span>
                      <span className="text-xs text-muted" title={`First ${fmtDateTime(edge.firstSeen)} · last ${fmtDateTime(edge.lastSeen)}`}>{timeAgo(edge.lastSeen)}</span>
                      <span className="text-xs"><Evidence e={edge} /></span>
                    </div>
                  );
                })}
              </div>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
