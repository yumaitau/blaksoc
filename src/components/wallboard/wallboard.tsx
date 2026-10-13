"use client";

import { ArrowLeft, ArrowRight, EyeOff, GripVertical, Maximize, Minimize, MoveHorizontal, RefreshCw, Shrink } from "lucide-react";
import { useEffect, useState, type DragEvent, type ReactNode } from "react";
import { BrandMark } from "@/components/soc/brand";
import { panelName, type PanelId, type WallboardPanel } from "@/lib/wallboard/layout";
import { WALLBOARD_SEVERITIES, type WallboardSnapshot } from "@/lib/wallboard/types";
import styles from "./wallboard.module.css";

const REFRESH_MS = 30_000;
const STALE_MS = 120_000;
const PAGE_SIZE = 6;
const ROTATE_MS = 15_000;
const number = new Intl.NumberFormat("en-AU");
const percent = new Intl.NumberFormat("en-AU", { style: "percent", maximumFractionDigits: 0 });
const clock = new Intl.DateTimeFormat("en-AU", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const hourMinute = new Intl.DateTimeFormat("en-AU", { hour: "2-digit", minute: "2-digit", hour12: false });
const date = new Intl.DateTimeFormat("en-AU", { weekday: "short", day: "numeric", month: "short" });
const RECOVERING = ["CONTAINED", "ERADICATED", "RECOVERED"];

/** "2d 4h", "3h 10m", "12m". Never seconds: a TV is read from across the room. */
export function duration(ms: number): string {
  const minutes = Math.max(0, Math.floor(ms / 60_000));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h${minutes % 60 ? ` ${minutes % 60}m` : ""}`;
  return `${Math.floor(hours / 24)}d${hours % 24 ? ` ${hours % 24}h` : ""}`;
}

type Feed = { data: WallboardSnapshot | null; error: string | null; denied: boolean; receivedAt: number };

export function Wallboard({ endpoint }: { endpoint: string }) {
  const [feed, setFeed] = useState<Feed>({ data: null, error: null, denied: false, receivedAt: 0 });
  const now = useNow();
  const page = useRotation();
  const [fullscreen, setFullscreen] = useState(false);
  const [controlError, setControlError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const onFullscreen = () => setFullscreen(!!document.fullscreenElement);
    document.addEventListener("fullscreenchange", onFullscreen);
    return () => document.removeEventListener("fullscreenchange", onFullscreen);
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

  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
      setControlError(null);
    } catch { setControlError("Full screen is unavailable in this browser. Use the browser’s full-screen mode."); }
  }

  return (
    <WallboardScreen
      data={data}
      now={now}
      page={page}
      message={message}
      waiting={<section className={styles.waiting} aria-live="polite"><RefreshCw aria-hidden="true" /><h2>{feed.denied || expired ? "Display access ended" : stale ? "Waiting for fresh data" : feed.error ? "Cannot reach the SOC" : "Getting the latest overview"}</h2><p>{message ?? "The display will update automatically."}</p>{feed.denied ? <a href="/login">Sign in</a> : <button type="button" onClick={() => setRefreshKey((value) => value + 1)}>Retry now</button>}</section>}
      controls={<><span role="status">{controlError}</span><button type="button" onClick={() => setRefreshKey((value) => value + 1)} aria-label="Refresh overview" title="Refresh overview"><RefreshCw aria-hidden="true" /></button><button type="button" onClick={toggleFullscreen} aria-label={fullscreen ? "Exit full screen" : "Enter full screen"} title={fullscreen ? "Exit full screen" : "Enter full screen"}>{fullscreen ? <Minimize aria-hidden="true" /> : <Maximize aria-hidden="true" />}</button></>}
    />
  );
}

/** Ticks every second for the clock, SLA countdowns and staleness. Zero until mounted, so SSR output is stable. */
export function useNow(): number {
  const [now, setNow] = useState(0);
  useEffect(() => {
    const tick = () => setNow(Date.now());
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

/** Customer pages advance together on a fixed cadence. */
export function useRotation(): number {
  const [page, setPage] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setPage((value) => value + 1), ROTATE_MS);
    return () => clearInterval(timer);
  }, []);
  return page;
}

export type PanelEditor = {
  dragging: PanelId | null;
  over: PanelId | null;
  onDragStart: (id: PanelId) => void;
  onDragOver: (id: PanelId) => void;
  /** `source` is the dragged panel id carried by the drag itself. */
  onDrop: (id: PanelId, source: string) => void;
  onDragEnd: () => void;
  onMove: (id: PanelId, dir: -1 | 1) => void;
  onResize: (id: PanelId, dir: -1 | 1) => void;
  onHide: (id: PanelId) => void;
};

/**
 * The office display. `embedded` renders inside a page (the layout designer) instead of filling the
 * screen; sizes follow the frame's width, so an embedded board is a faithful scale model of the TV.
 */
export function WallboardScreen({ data, now, page, message = null, layout, editor, embedded = false, waiting, controls }: {
  data: WallboardSnapshot | null;
  now: number;
  page: number;
  message?: string | null;
  layout?: WallboardPanel[];
  editor?: PanelEditor;
  embedded?: boolean;
  waiting?: ReactNode;
  controls?: ReactNode;
}) {
  const counts = data?.counts;
  const health = data?.customers.reduce((sum, row) => sum + row.healthAlerts, 0) ?? 0;
  const attention = !!counts && (counts.criticalAlerts > 0 || counts.overdueIncidents > 0);
  const panels = (layout ?? data?.layout ?? []).filter((panel) => !panel.hidden);

  return (
    <div className={`${styles.frame} ${embedded ? styles.embedded : styles.live}`}>
      <main className={styles.board}>
        <header className={styles.header}>
          <div className={styles.identity}>
            <BrandMark className={styles.logo} />
            <div><h1>blak<span className={styles.accent}>SOC</span> <span className={styles.subtitle}>Operations overview</span></h1><p>{data ? data.customerCount === 1 ? data.scopeName : `${number.format(data.customerCount)} customers in scope` : "SOC wallboard"}</p></div>
          </div>
          {data?.preview ? <span className={styles.previewTag}>Preview · not published</span> : null}
          <div className={styles.time}><time suppressHydrationWarning>{now ? clock.format(now) : "—"}</time><span>{now ? date.format(now) : ""}</span></div>
        </header>

        <div className={styles.status} role="status">
          <span className={message ? styles.warning : attention ? styles.danger : styles.good}>{message ? "Updates interrupted" : data ? attention ? "Attention required" : "No critical queue or overdue SLA" : "Connecting to the SOC…"}</span>
          <span>{message ?? (data ? `${number.format(counts!.newLastHour)} new in the last hour · ${number.format(counts!.unassigned)} unassigned · ${number.format(health)} telemetry health alert${health === 1 ? "" : "s"}` : "Loading current operational data")}</span>
        </div>

        {data ? (
          <div className={styles.panels}>
            {panels.map((panel) => <PanelFrame key={panel.id} panel={panel} editor={editor}>{renderPanel(panel.id, data, now, page)}</PanelFrame>)}
            {!panels.length ? <p className={styles.empty}>No panels are shown. Add one from the hidden panels list.</p> : null}
          </div>
        ) : waiting ?? <section className={styles.waiting}><RefreshCw aria-hidden="true" /><h2>Getting the latest overview</h2></section>}

        <footer className={styles.footer}>
          <p aria-live="polite">{data ? <>Updated {clock.format(Date.parse(data.generatedAt))} · refreshes every 30s{data.linkExpiresAt ? ` · link expires ${new Date(data.linkExpiresAt).toLocaleDateString("en-AU")}` : ""}</> : "Read-only office display"}</p>
          {controls ? <div className={styles.controls}>{controls}</div> : null}
        </footer>
      </main>
    </div>
  );
}

function PanelFrame({ panel, editor, children }: { panel: WallboardPanel; editor?: PanelEditor; children: ReactNode }) {
  const span = styles[panel.span];
  if (!editor) return <div className={`${styles.cell} ${span}`}>{children}</div>;
  const name = panelName(panel.id);
  const drop = (event: DragEvent) => { event.preventDefault(); editor.onDrop(panel.id, event.dataTransfer.getData("text/plain")); };
  return (
    <div
      className={`${styles.cell} ${span} ${styles.editing} ${editor.dragging === panel.id ? styles.dragging : ""} ${editor.over === panel.id && editor.dragging !== panel.id ? styles.dropTarget : ""}`}
      draggable
      onDragStart={(event) => {
        event.dataTransfer.effectAllowed = "move";
        event.dataTransfer.setData("text/plain", panel.id);
        // Restyling the source inside dragstart can cancel Chrome's native drag; mark it on the next frame.
        requestAnimationFrame(() => editor.onDragStart(panel.id));
      }}
      onDragOver={(event) => { event.preventDefault(); event.dataTransfer.dropEffect = "move"; editor.onDragOver(panel.id); }}
      onDrop={drop}
      onDragEnd={editor.onDragEnd}
    >
      <div className={styles.toolbar}>
        <GripVertical aria-hidden="true" className={styles.grip} />
        <span>{name}</span>
        <button type="button" onClick={() => editor.onMove(panel.id, -1)} aria-label={`Move ${name} earlier`} title="Move earlier"><ArrowLeft aria-hidden="true" /></button>
        <button type="button" onClick={() => editor.onMove(panel.id, 1)} aria-label={`Move ${name} later`} title="Move later"><ArrowRight aria-hidden="true" /></button>
        <button type="button" onClick={() => editor.onResize(panel.id, -1)} aria-label={`Make ${name} narrower`} title="Narrower"><Shrink aria-hidden="true" /></button>
        <button type="button" onClick={() => editor.onResize(panel.id, 1)} aria-label={`Make ${name} wider`} title="Wider"><MoveHorizontal aria-hidden="true" /></button>
        <button type="button" onClick={() => editor.onHide(panel.id)} aria-label={`Hide ${name}`} title="Hide"><EyeOff aria-hidden="true" /></button>
      </div>
      {children}
    </div>
  );
}

function renderPanel(id: PanelId, data: WallboardSnapshot, now: number, page: number): ReactNode {
  switch (id) {
    case "metrics": return <Metrics data={data} now={now} />;
    case "customers": return <Customers data={data} page={page} />;
    case "incidents": return <Incidents data={data} now={now} />;
    case "activity": return <Activity activity={data.activity} />;
    case "severity": return <Severity data={data} />;
    case "flow": return <Flow data={data} now={now} />;
    case "techniques": return <Techniques data={data} />;
  }
}

function Panel({ id, heading, meta, children }: { id: string; heading: string; meta?: ReactNode; children: ReactNode }) {
  return <section className={styles.panel} aria-labelledby={`${id}-heading`}><div className={styles.panelHead}><h2 id={`${id}-heading`}>{heading}</h2>{meta ? <span>{meta}</span> : null}</div>{children}</section>;
}

function Metrics({ data, now }: { data: WallboardSnapshot; now: number }) {
  const counts = data.counts;
  const endpoints = data.customers.reduce((sum, row) => sum + row.endpoints, 0);
  const offline = data.customers.reduce((sum, row) => sum + row.offlineEndpoints, 0);
  const waited = data.oldestUntriagedAt && now ? `Oldest waiting ${duration(now - Date.parse(data.oldestUntriagedAt))}` : `${number.format(counts.openAlerts)} open alerts`;
  return (
    <section className={styles.metrics} aria-label="Current operational totals">
      <Metric label="Critical / high-risk" value={number.format(counts.criticalAlerts)} detail="Open alerts · risk ≥80 or critical" tone={counts.criticalAlerts ? "danger" : undefined} />
      <Metric label="Awaiting triage" value={number.format(counts.awaitingTriage)} detail={waited} />
      <Metric label="Active incidents" value={number.format(counts.activeIncidents)} detail={`${number.format(counts.overdueIncidents)} overdue SLA`} tone={counts.overdueIncidents ? "danger" : undefined} />
      <Metric label="Pending approvals" value={number.format(counts.pendingApprovals)} detail="Response decisions waiting" tone={counts.pendingApprovals ? "warning" : undefined} />
      <Metric label="Threat-intel matches" value={number.format(counts.intelMatched)} detail="Open alerts on known-bad indicators" tone={counts.intelMatched ? "warning" : undefined} />
      <Metric label="Endpoints reporting" value={endpoints ? percent.format((endpoints - offline) / endpoints) : "—"} detail={`${number.format(offline)} not active · ${number.format(endpoints)} inventoried`} tone={offline ? "warning" : undefined} />
    </section>
  );
}

function Metric({ label, value, detail, tone }: { label: string; value: string; detail: string; tone?: "danger" | "warning" }) {
  return <div className={styles.metric}><h2>{label}</h2><strong className={tone ? styles[tone] : undefined}>{value}</strong><p>{detail}</p></div>;
}

function Customers({ data, page }: { data: WallboardSnapshot; page: number }) {
  const pages = Math.max(1, Math.ceil(data.customers.length / PAGE_SIZE));
  const current = page % pages;
  const rows = data.customers.slice(current * PAGE_SIZE, (current + 1) * PAGE_SIZE);
  return (
    <Panel id="customers" heading="Customer posture" meta={pages > 1 ? `Page ${current + 1} / ${pages} · rotates every 15s` : "Highest risk first"}>
      {rows.length ? <table className={styles.customers}><thead><tr><th scope="col">Customer</th><th scope="col">Risk</th><th scope="col" className={styles.optional}>Triage</th><th scope="col">Alerts</th><th scope="col">Cases</th><th scope="col" className={styles.optional}>Not active</th></tr></thead><tbody>{rows.map((customer) => <tr key={customer.id}>
        <th scope="row"><span>{customer.name}</span><small>{customer.criticalAlerts ? `${customer.criticalAlerts} critical / high-risk` : customer.healthAlerts ? `${customer.healthAlerts} health alert${customer.healthAlerts === 1 ? "" : "s"}` : "No critical queue"}</small></th>
        <td className={customer.risk >= 80 ? styles.danger : customer.risk >= 60 ? styles.warning : undefined}>{customer.risk}<small>/100</small></td>
        <td className={styles.optional}>{number.format(customer.awaitingTriage)}</td>
        <td>{number.format(customer.openAlerts)}</td>
        <td>{number.format(customer.activeIncidents)}</td>
        <td className={`${styles.optional} ${customer.offlineEndpoints ? styles.warning : ""}`}>{number.format(customer.offlineEndpoints)}<small> / {number.format(customer.endpoints)}</small></td>
      </tr>)}</tbody></table> : <p className={styles.empty}>No operational customers in this scope.</p>}
    </Panel>
  );
}

function Incidents({ data, now }: { data: WallboardSnapshot; now: number }) {
  return (
    <Panel id="incidents" heading="Priority incidents" meta={`${data.incidentSummary.length} of ${number.format(data.counts.activeIncidents)} active`}>
      {data.incidentSummary.length ? <ul className={styles.incidents}>{data.incidentSummary.map((incident) => {
        const due = incident.slaDueAt ? Date.parse(incident.slaDueAt) : null;
        const recovering = RECOVERING.includes(incident.status);
        const overdue = due !== null && now > 0 && due < now && !recovering;
        const status = incident.status.charAt(0) + incident.status.slice(1).replaceAll("_", " ").toLowerCase();
        const sla = due === null || recovering || !now ? status : overdue ? `SLA overdue ${duration(now - due)}` : `SLA in ${duration(due - now)}`;
        const soon = !overdue && due !== null && !recovering && now > 0 && due - now < 3600_000;
        return <li key={incident.id}>
          <div><span className={styles.reference}>INC-{incident.ref}</span><span className={incident.severity === "critical" ? styles.danger : incident.severity === "high" ? styles.warning : styles.secondary}>{incident.severity}</span></div>
          <p>{incident.tenantName}<small>{now ? `Opened ${duration(now - Date.parse(incident.createdAt))} ago` : ""}</small></p>
          <span className={overdue ? styles.danger : soon ? styles.warning : styles.secondary}>{sla}</span>
        </li>;
      })}</ul> : <p className={styles.empty}>No active incidents.</p>}
    </Panel>
  );
}

function Activity({ activity }: { activity: WallboardSnapshot["activity"] }) {
  const peak = Math.max(1, ...activity.map((bucket) => bucket.count));
  const total = activity.reduce((sum, bucket) => sum + bucket.count, 0);
  const busiest = total ? activity.reduce((top, bucket) => bucket.count > top.count ? bucket : top) : null;
  return (
    <Panel id="activity" heading="Alert activity" meta="Last 24 hours · all lanes">
      <p className={styles.figure}><strong>{number.format(total)}</strong> alerts received{busiest ? ` · peak ${number.format(busiest.count)} at ${hourMinute.format(Date.parse(busiest.hour))}` : ""}</p>
      <div className={styles.bars} role="img" aria-label={`${number.format(total)} alerts received across the last 24 hourly buckets. Peak ${number.format(busiest?.count ?? 0)} alerts per hour.`}>{activity.map((bucket) => <div key={bucket.hour} title={`${hourMinute.format(Date.parse(bucket.hour))}: ${bucket.count} alerts`} style={{ height: `${Math.max(bucket.count ? 3 : 0, bucket.count / peak * 100)}%` }} />)}</div>
      <div className={styles.axis}><span>{activity[0] ? hourMinute.format(Date.parse(activity[0].hour)) : "24h ago"}</span><span>Now</span></div>
    </Panel>
  );
}

function Severity({ data }: { data: WallboardSnapshot }) {
  const total = WALLBOARD_SEVERITIES.reduce((sum, key) => sum + data.severity[key], 0);
  return (
    <Panel id="severity" heading="Open alerts by severity" meta={`${number.format(total)} open · active lane`}>
      <div className={styles.stack} role="img" aria-label={WALLBOARD_SEVERITIES.map((key) => `${data.severity[key]} ${key}`).join(", ")}>
        {total ? WALLBOARD_SEVERITIES.map((key) => data.severity[key] ? <div key={key} className={styles[`sev-${key}`]} style={{ flexGrow: data.severity[key] }} /> : null) : null}
      </div>
      <ul className={styles.legend}>{WALLBOARD_SEVERITIES.map((key) => <li key={key}><span className={`${styles.swatch} ${styles[`sev-${key}`]}`} aria-hidden="true" /><span>{key === "informational" ? "Info" : key}</span><strong>{number.format(data.severity[key])}</strong></li>)}</ul>
    </Panel>
  );
}

function Flow({ data, now }: { data: WallboardSnapshot; now: number }) {
  const counts = data.counts;
  return (
    <Panel id="flow" heading="Queue flow" meta="Intake and closure">
      <dl className={styles.facts}>
        <div><dt>New in the last hour</dt><dd className={counts.newLastHour >= 20 ? styles.warning : undefined}>{number.format(counts.newLastHour)}</dd></div>
        <div><dt>Alerts closed · 24h</dt><dd>{number.format(counts.closedLast24h)}</dd></div>
        <div><dt>Oldest untriaged</dt><dd className={data.oldestUntriagedAt && now - Date.parse(data.oldestUntriagedAt) > 4 * 3600_000 ? styles.warning : undefined}>{data.oldestUntriagedAt && now ? duration(now - Date.parse(data.oldestUntriagedAt)) : "—"}</dd></div>
        <div><dt>Unassigned alerts</dt><dd>{number.format(counts.unassigned)}</dd></div>
        <div><dt>Incidents opened · 24h</dt><dd>{number.format(counts.incidentsOpened24h)}</dd></div>
        <div><dt>Incidents closed · 24h</dt><dd>{number.format(counts.incidentsClosed24h)}</dd></div>
      </dl>
    </Panel>
  );
}

function Techniques({ data }: { data: WallboardSnapshot }) {
  const peak = Math.max(1, ...data.techniques.map((t) => t.count));
  return (
    <Panel id="techniques" heading="ATT&CK techniques" meta="Most seen · last 24 hours">
      {data.techniques.length ? <ul className={styles.techniques}>{data.techniques.map((t) => <li key={t.id}>
        <span className={styles.reference}>{t.id}</span><span>{t.name ?? "Unmapped technique"}</span><strong>{number.format(t.count)}</strong>
        <div aria-hidden="true"><div style={{ width: `${t.count / peak * 100}%` }} /></div>
      </li>)}</ul> : <p className={styles.empty}>No techniques mapped in the last 24 hours.</p>}
    </Panel>
  );
}
