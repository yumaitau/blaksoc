import { notFound } from "next/navigation";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { severityLabel, statusLabel } from "@/lib/portal/summary";
import { portalIncident } from "@/lib/services/portal";
import { fmtDateTime } from "@/lib/utils";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return { title: `Incident ${id.slice(0, 8)}` };
}

export default async function PortalIncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const ctx = await requireAccess();
  const data = await portalIncident(ctx, id);
  if (!data) notFound();
  const canAck = can(ctx, "portal:read", data.tenantId);
  const [happened, did, need] = data.sentences;

  return (
    <article className="space-y-4">
      <p className="text-sm text-muted">{data.tenantName}</p>
      <h1 className="text-xl font-semibold">INC-{data.incident.ref}: {data.incident.title}</h1>
      <p className="text-sm">{severityLabel(data.incident.severity)} severity. Status: {statusLabel(data.incident.status)}. Updated {fmtDateTime(data.incident.updatedAt)}.</p>
      <section aria-labelledby="happened">
        <h2 id="happened" className="text-base font-semibold">What happened</h2>
        <p className="mt-1 text-sm">{happened}</p>
      </section>
      <section aria-labelledby="did">
        <h2 id="did" className="text-base font-semibold">What we did</h2>
        <p className="mt-1 text-sm">{did}</p>
      </section>
      <section aria-labelledby="need">
        <h2 id="need" className="text-base font-semibold">What you need to do</h2>
        <p className="mt-1 text-sm">{need}</p>
      </section>
      {data.acknowledgedAt ? (
        <p className="text-sm" role="status">You told us you have read this on {fmtDateTime(data.acknowledgedAt)}.</p>
      ) : canAck ? (
        <form action={`/portal/incidents/${data.incident.id}/ack`} method="post">
          <button className="inline-flex min-h-11 items-center rounded-md bg-accent px-4 font-medium text-accent-fg" type="submit">I&apos;ve read this</button>
        </form>
      ) : (
        <p className="text-sm text-muted">A customer administrator can confirm they have read this.</p>
      )}
      <p><a className="inline-flex min-h-11 items-center underline" href="/portal">Back to overview</a></p>
    </article>
  );
}
