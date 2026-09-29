import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { actionPhrase, incidentSentences, severityLabel, statusLabel } from "@/lib/portal/summary";
import { customerForPortal, portalOverview } from "@/lib/services/portal";
import { fmtDateTime, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";

export const metadata = { title: "Security overview" };

const ACTION_OK = new Set(["SUCCEEDED"]);

export default async function PortalPage() {
  const ctx = await requireAccess();
  const ws = await currentWorkspace(ctx);
  const tenant = customerForPortal(ctx, ws.tenant);
  if (!tenant) {
    return (
      <div>
        <h1 className="text-xl font-semibold">Security overview</h1>
        <p className="mt-2 text-sm text-muted">Your account is not linked to a customer organisation yet.</p>
      </div>
    );
  }
  const o = await portalOverview(ctx, tenant.id);
  if (!o) return <p className="text-sm text-muted">Organisation not found.</p>;

  const top = o.activeIncidents[0];
  const phrases = top
    ? o.actions.filter((a) => a.incidentId === top.id && ACTION_OK.has(a.status)).map((a) => actionPhrase(a.action))
    : [];
  const sentences = top ? incidentSentences({ title: top.title, severity: top.severity, status: top.status, actions: phrases }) : null;
  const canAssets = can(ctx, "asset:read", tenant.id);
  const canApprove = can(ctx, "response:approve", tenant.id);
  const recs = o.recommendations.filter((r) => (canAssets || !r.href.startsWith("/assets")) && (canApprove || r.href !== "/soc/approvals"));
  const level = o.overallRisk >= 80 ? "critical" : o.overallRisk >= 60 ? "elevated" : o.overallRisk >= 40 ? "moderate" : "low";

  return (
    <div className="space-y-6">
      <header>
        <p className="text-sm text-muted">{ctx.isPlatform ? "Customer portal preview" : tenant.name}</p>
        <h1 className="text-xl font-semibold">{o.tenant.name}: security overview</h1>
        <p className="mt-2 text-sm">Your current security risk is {level} ({o.overallRisk} out of 100).</p>
      </header>

      {sentences && top ? (
        <section aria-labelledby="plain-summary">
          <h2 id="plain-summary" className="text-base font-semibold">Latest incident, in brief</h2>
          <p className="mt-2 text-sm">{sentences[0]}</p>
          <p className="mt-1 text-sm">{sentences[1]}</p>
          <p className="mt-1 text-sm">{sentences[2]}</p>
          <a className="mt-2 inline-flex min-h-11 items-center underline" href={`/portal/incidents/${top.id}`}>Open INC-{top.ref}</a>
        </section>
      ) : (
        <p className="text-sm text-muted">No active incident.</p>
      )}

      <section aria-labelledby="incidents">
        <h2 id="incidents" className="text-base font-semibold">Active incidents</h2>
        {o.activeIncidents.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No active incidents.</p>
        ) : (
          <ul className="mt-2 divide-y divide-border border-y border-border">
            {o.activeIncidents.map((i) => (
              <li key={i.id}>
                <a className="flex min-h-11 flex-col justify-center py-2 underline-offset-2 hover:underline" href={`/portal/incidents/${i.id}`}>
                  <span className="text-sm font-medium">INC-{i.ref}: {i.title}</span>
                  <span className="text-sm text-muted">{severityLabel(i.severity)} · {statusLabel(i.status)} · updated {timeAgo(i.updatedAt)}</span>
                </a>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="need">
        <h2 id="need" className="text-base font-semibold">What we recommend</h2>
        {recs.length === 0 ? (
          <p className="mt-2 text-sm text-muted">Nothing needs your attention right now.</p>
        ) : (
          <ul className="mt-2 space-y-2">
            {recs.map((r) => (
              <li key={r.text}>
                <a className="inline-flex min-h-11 items-center text-sm underline" href={r.href}>
                  <span className="mr-2 uppercase">{r.priority}.</span>{r.text}
                </a>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="coverage" className="text-sm">
        <h2 id="coverage" className="text-base font-semibold">Coverage</h2>
        <ul className="mt-2 space-y-1">
          <li>{o.endpoints.online} of {o.endpoints.total} protected devices are online. {o.endpoints.offline} offline. {o.endpoints.unmanaged} have no agent.</li>
          <li>{o.kevCves} actively exploited weakness{o.kevCves === 1 ? "" : "es"}.</li>
          <li>{o.pendingApprovals} containment request{o.pendingApprovals === 1 ? "" : "s"} waiting for approval.</li>
          <li>In the last 30 days the SOC reviewed {o.alertStats.last30} detection{o.alertStats.last30 === 1 ? "" : "s"} and closed {o.alertStats.closed30}.</li>
        </ul>
      </section>

      {o.latestReport ? (
        <p className="text-sm">
          {/* eslint-disable-next-line @next/next/no-html-link-for-pages -- plain anchor; the rule misreads /reports as /reports/[id], and next/link pulls the client router */}
          <a className="underline" href="/reports">Latest report: {o.latestReport.title}</a> ({fmtDateTime(o.latestReport.createdAt)}).
        </p>
      ) : null}

      {o.threats.length ? (
        <section aria-labelledby="threats">
          <h2 id="threats" className="text-base font-semibold">Threats relevant to you</h2>
          <ul className="mt-2 space-y-2">
            {o.threats.map((t) => (
              <li key={t.id}>
                <a className="text-sm underline" href={t.url} target="_blank" rel="noreferrer">{t.title}<span className="sr-only"> (opens in a new tab)</span></a>
                <span className="block text-sm text-muted">{t.source} · {fmtDateTime(t.publishedAt)}{t.affectsEstate ? " · affects your systems" : ""}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
