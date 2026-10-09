"use client";

import { Maximize, Minimize, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { BrandMark } from "@/components/soc/brand";
import type { WallboardSnapshot } from "@/lib/wallboard/types";
import styles from "./wallboard.module.css";

const REFRESH_MS = 30_000;
const STALE_MS = 120_000;
const PAGE_SIZE = 6;
const number = new Intl.NumberFormat("en-AU");
const clock = new Intl.DateTimeFormat("en-AU", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const date = new Intl.DateTimeFormat("en-AU", { weekday: "short", day: "numeric", month: "short" });

type Feed = { data: WallboardSnapshot | null; error: string | null; denied: boolean; receivedAt: number };

export function Wallboard({ endpoint }: { endpoint: string }) {
  const [feed, setFeed] = useState<Feed>({ data: null, error: null, denied: false, receivedAt: 0 });
  const [now, setNow] = useState(0);
  const [page, setPage] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);
  const [controlError, setControlError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const tick = () => setNow(Date.now());
    tick();
    const timer = setInterval(tick, 1000);
    const rotation = setInterval(() => setPage((value) => value + 1), 15_000);
    const onFullscreen = () => setFullscreen(!!document.fullscreenElement);
    document.addEventListener("fullscreenchange", onFullscreen);
    return () => {
      clearInterval(timer);
      clearInterval(rotation);
      document.removeEventListener("fullscreenchange", onFullscreen);
    };
  }, []);

  useEffect(() => {
    let stopped = false;
    let next: ReturnType<typeof setTimeout> | undefined;
    let controller: AbortController;
    async function poll() {
      controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15_000);
      try {
        const response = await fetch(endpoint, { cache: "no-store", credentials: "same-origin", signal: controller.signal });
        if (stopped) return;
        if (response.status === 401 || response.status === 403) {
          setFeed({ data: null, receivedAt: 0, denied: true, error: "Access has ended. Ask a SOC manager for a new display link, or sign in again." });
          return;
        }
        if (!response.ok) throw new Error("unavailable");
        const data: WallboardSnapshot = await response.json();
        if (!stopped) setFeed({ data, receivedAt: Date.now(), denied: false, error: null });
      } catch {
        if (!stopped) setFeed((previous) => ({ ...previous, error: "Updates unavailable. Retrying every 30 seconds." }));
      } finally {
        clearTimeout(timeout);
      }
      if (!stopped) next = setTimeout(poll, REFRESH_MS);
    }
    void poll();
    return () => { stopped = true; clearTimeout(next); controller?.abort(); };
  }, [endpoint, refreshKey]);

  const expired = !!feed.data?.linkExpiresAt && now >= Date.parse(feed.data.linkExpiresAt);
  const stale = !!feed.data && now - feed.receivedAt >= STALE_MS;
  const data = expired || stale ? null : feed.data;
  const message = expired ? "This display link has expired. Ask a SOC manager for a new link." : stale ? "Data is out of date. Waiting for the connection to recover." : feed.error;
  const pages = Math.max(1, Math.ceil((data?.customers.length ?? 0) / PAGE_SIZE));
  const currentPage = page % pages;
  const customers = data?.customers.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE) ?? [];
  const endpoints = data?.customers.reduce((sum, row) => sum + row.endpoints, 0) ?? 0;
  const offline = data?.customers.reduce((sum, row) => sum + row.offlineEndpoints, 0) ?? 0;
  const health = data?.customers.reduce((sum, row) => sum + row.healthAlerts, 0) ?? 0;
  const counts = data?.counts;
  const attention = !!counts && (counts.criticalAlerts > 0 || counts.overdueIncidents > 0);

  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
      setControlError(null);
    } catch { setControlError("Full screen is unavailable in this browser. Use the browser’s full-screen mode."); }
  }

  return (
    <main className={styles.board}>
      <header className={styles.header}>
        <div className={styles.identity}>
          <BrandMark className={styles.logo} />
          <div><h1>blak<span className={styles.accent}>SOC</span> <span className={styles.title}>Operations overview</span></h1><p>{data ? data.customerCount === 1 ? data.scopeName : `${number.format(data.customerCount)} customers in scope` : "SOC wallboard"}</p></div>
        </div>
        <div className={styles.time}><time suppressHydrationWarning>{now ? clock.format(now) : "—"}</time><span>{now ? date.format(now) : ""}</span></div>
      </header>

      <div className={styles.status} role="status">
        <span className={message ? styles.warning : attention ? styles.danger : styles.good}>{message ? "Updates interrupted" : data ? attention ? "Attention required" : "No critical queue or overdue SLA" : "Connecting to the SOC…"}</span>
        <span>{message ?? (data ? `${counts!.unassigned} unassigned alerts · ${health} telemetry health alert${health === 1 ? "" : "s"}` : "Loading current operational data")}</span>
      </div>

      {data ? <>
        <section className={styles.metrics} aria-label="Current operational totals">
          <Metric label="Critical / high-risk" value={counts!.criticalAlerts} detail="Open active alerts · risk ≥80 or critical" tone={counts!.criticalAlerts ? "danger" : undefined} />
          <Metric label="Awaiting triage" value={counts!.awaitingTriage} detail={`${number.format(counts!.openAlerts)} total open alerts`} />
          <Metric label="Active incidents" value={counts!.activeIncidents} detail={`${number.format(counts!.overdueIncidents)} overdue SLA`} tone={counts!.overdueIncidents ? "danger" : undefined} />
          <Metric label="Pending approvals" value={counts!.pendingApprovals} detail="Response decisions waiting" tone={counts!.pendingApprovals ? "warning" : undefined} />
          <Metric label="Endpoint reporting" value={endpoints - offline} detail={`${number.format(offline)} not active · ${number.format(endpoints)} inventoried`} tone={offline ? "warning" : undefined} />
        </section>

        <div className={styles.content}>
          <section className={`${styles.panel} ${styles.customerPanel}`} aria-labelledby="customers-heading">
            <div className={styles.sectionHead}><h2 id="customers-heading">Customer posture</h2><span>{pages > 1 ? `Page ${currentPage + 1} / ${pages} · rotates every 15s` : "Current queue & coverage"}</span></div>
            {customers.length ? <table className={styles.customers}><thead><tr><th scope="col">Customer</th><th scope="col">Risk</th><th scope="col">Alerts</th><th scope="col">Cases</th><th scope="col">Not active</th></tr></thead><tbody>{customers.map((customer) => <tr key={customer.id}>
              <th scope="row"><span>{customer.name}</span><small>{customer.criticalAlerts ? `${customer.criticalAlerts} critical / high-risk` : customer.healthAlerts ? `${customer.healthAlerts} health alert${customer.healthAlerts === 1 ? "" : "s"}` : "No critical queue"}</small></th>
              <td className={customer.risk >= 80 ? styles.danger : customer.risk >= 60 ? styles.warning : undefined}>{customer.risk}<small>/100</small></td><td>{number.format(customer.openAlerts)}</td><td>{number.format(customer.activeIncidents)}</td><td className={customer.offlineEndpoints ? styles.warning : undefined}>{number.format(customer.offlineEndpoints)}<small> / {number.format(customer.endpoints)}</small></td>
            </tr>)}</tbody></table> : <p className={styles.empty}>No operational customers in this scope.</p>}
          </section>

          <section className={styles.panel} aria-labelledby="activity-heading">
            <div className={styles.sectionHead}><h2 id="activity-heading">Alert activity</h2><span>Last 24 hourly buckets · all lanes</span></div>
            <Activity activity={data.activity} />
          </section>

          <section className={styles.panel} aria-labelledby="incidents-heading">
            <div className={styles.sectionHead}><h2 id="incidents-heading">Priority incidents</h2><span>{Math.min(4, data.incidentSummary.length)} of {number.format(counts!.activeIncidents)} active</span></div>
            {data.incidentSummary.length ? <ul className={styles.incidents}>{data.incidentSummary.slice(0, 4).map((incident) => {
              const overdue = !!incident.slaDueAt && Date.parse(incident.slaDueAt) < now && !["CONTAINED", "ERADICATED", "RECOVERED"].includes(incident.status);
              return <li key={incident.id}><div><span className={styles.reference}>INC-{incident.ref}</span><span className={incident.severity === "critical" ? styles.danger : incident.severity === "high" ? styles.warning : styles.secondary}>{incident.severity}</span></div><p>{incident.tenantName}</p><span className={overdue ? styles.danger : styles.secondary}>{overdue ? "SLA overdue" : incident.status.replaceAll("_", " ").toLowerCase()}</span></li>;
            })}</ul> : <p className={styles.empty}>No active incidents.</p>}
          </section>
        </div>
      </> : <section className={styles.waiting} aria-live="polite"><RefreshCw aria-hidden="true" /><h2>{feed.denied || expired ? "Display access ended" : stale ? "Waiting for fresh data" : feed.error ? "Cannot reach the SOC" : "Getting the latest overview"}</h2><p>{message ?? "The display will update automatically."}</p>{feed.denied ? <a href="/login">Sign in</a> : <button type="button" onClick={() => setRefreshKey((value) => value + 1)}>Retry now</button>}</section>}

      <footer className={styles.footer}>
        <p aria-live="polite">{data ? <>Updated {clock.format(Date.parse(data.generatedAt))} · refreshes every 30s{data.linkExpiresAt ? ` · link expires ${new Date(data.linkExpiresAt).toLocaleDateString("en-AU")}` : ""}</> : "Read-only office display"}</p>
        <div className={styles.controls}><span role="status">{controlError}</span><button type="button" onClick={() => setRefreshKey((value) => value + 1)} aria-label="Refresh overview" title="Refresh overview"><RefreshCw aria-hidden="true" /></button><button type="button" onClick={toggleFullscreen} aria-label={fullscreen ? "Exit full screen" : "Enter full screen"} title={fullscreen ? "Exit full screen" : "Enter full screen"}>{fullscreen ? <Minimize aria-hidden="true" /> : <Maximize aria-hidden="true" />}</button></div>
      </footer>
    </main>
  );
}

function Metric({ label, value, detail, tone }: { label: string; value: number; detail: string; tone?: "danger" | "warning" }) {
  return <div className={styles.metric}><h2>{label}</h2><strong className={tone ? styles[tone] : undefined}>{number.format(value)}</strong><p>{detail}</p></div>;
}

function Activity({ activity }: { activity: WallboardSnapshot["activity"] }) {
  const peak = Math.max(1, ...activity.map((bucket) => bucket.count));
  const total = activity.reduce((sum, bucket) => sum + bucket.count, 0);
  return <><p className={styles.activityTotal}><strong>{number.format(total)}</strong> alerts received</p><div className={styles.bars} role="img" aria-label={`${number.format(total)} alerts received across the last 24 hourly buckets. Peak ${number.format(peak === 1 && total === 0 ? 0 : peak)} alerts per hour.`}>{activity.map((bucket) => <div key={bucket.hour} title={`${new Date(bucket.hour).toLocaleTimeString("en-AU", { hour: "2-digit", minute: "2-digit" })}: ${bucket.count} alerts`} style={{ height: `${Math.max(bucket.count ? 3 : 0, bucket.count / peak * 100)}%` }} />)}</div><div className={styles.axis}><span>{activity[0] ? new Date(activity[0].hour).toLocaleTimeString("en-AU", { hour: "2-digit", minute: "2-digit" }) : "24h ago"}</span><span>Now</span></div></>;
}
