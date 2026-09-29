import { ArrowLeft, Download } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { AccessDenied } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import type { BoardLight, ReportSection } from "@/lib/reports/types";
import { getReport } from "@/lib/services/reports";
import { cn, fmtDateTime } from "@/lib/utils";

/** No report:read anywhere reads the same as "no such report". */
const denied = (err: unknown) => {
  if (err instanceof AccessDenied) return null;
  throw err;
};

export const metadata = { title: "Report" };

const LIGHT_WORD: Record<BoardLight, string> = {
  steady: "Steady",
  look: "Needs a look",
  now: "Needs attention now",
};

function BasisTag({ s }: { s: ReportSection }) {
  return s.basis === "observed" ? (
    <Badge variant="ok" className="uppercase tracking-wider">Observed · evidence</Badge>
  ) : (
    <Badge variant="warn" className="uppercase tracking-wider">Interpretation{s.author ? ` · ${s.author}` : ""}</Badge>
  );
}

export default async function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const ctx = await requireAccess();
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) notFound();
  const report = await getReport(ctx, id).catch(denied);
  if (!report) notFound();
  const c = report.content;

  return (
    <div className="space-y-5">
      <Link href="/reports" className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg"><ArrowLeft className="size-3.5" />All reports</Link>
      {c.cobrand ? <p className="text-sm font-medium">{c.cobrand}</p> : null}
      <PageHeader
        eyebrow={c.tenantName}
        title={report.title}
        description={`Period ${fmtDateTime(c.period.start)} to ${fmtDateTime(c.period.end)} · generated ${fmtDateTime(c.generatedAt)}`}
        actions={(["pdf", "csv", "json"] as const).map((f) => (
          <a key={f} href={`/api/reports/${report.id}/export?format=${f}`} className={buttonVariants({ variant: f === "pdf" ? "default" : "secondary", size: "sm" })}>
            <Download />{f.toUpperCase()}
          </a>
        )).concat(report.kind === "board_summary" ? [
          <a key="slides" href={`/api/reports/${report.id}/export?format=slides`} className={buttonVariants({ variant: "secondary", size: "sm" })}>
            <Download />Slides
          </a>,
        ] : [])}
      />

      {/* eslint-disable-next-line @next/next/no-img-element */}
      {c.image ? <img src={`data:${c.image.mime};base64,${c.image.data}`} alt="Image chosen by the group" className="max-h-28 rounded-md" /> : null}
      {c.light ? (
        <p className={cn(
          "rounded-md border px-4 py-3 text-lg font-semibold text-fg",
          c.light === "now" ? "border-danger bg-danger/10" : c.light === "look" ? "border-warn bg-warn/10" : "border-ok bg-ok/10",
        )}>
          {LIGHT_WORD[c.light]}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-border bg-surface px-4 py-2.5 text-xs text-muted">
        <span className="flex items-center gap-2"><Badge variant="ok">OBSERVED</Badge>facts from telemetry and case records</span>
        <span className="flex items-center gap-2"><Badge variant="warn">INTERPRETATION</Badge>analyst, AI or system judgement. Not evidence.</span>
      </div>

      {c.sections.map((s, i) => (
        <Card key={i} className={cn("border-l-2", s.basis === "observed" ? "border-l-ok/60" : "border-l-warn/60")}>
          <CardHeader>
            <CardTitle>{s.heading}</CardTitle>
            <BasisTag s={s} />
          </CardHeader>
          {s.body ? <CardContent className={cn("whitespace-pre-wrap", report.kind === "board_summary" ? "text-base leading-relaxed" : "text-sm", s.basis === "interpretation" && "italic text-muted")}>{s.body}</CardContent> : null}
          {s.links?.length ? (
            <CardContent className="flex flex-col gap-1 text-sm">
              <p className="text-xs font-medium text-muted">Evidence</p>
              {s.links.map((link) => <Link key={link.href} href={link.href} className="underline">{link.label}</Link>)}
            </CardContent>
          ) : null}
          {s.table ? (
            s.table.rows.length ? (
              <Table>
                <THead>
                  <TR className="hover:bg-transparent">{s.table.columns.map((col) => <TH key={col}>{col}</TH>)}</TR>
                </THead>
                <TBody>
                  {s.table.rows.map((r, j) => (
                    <TR key={j}>{r.map((v, k) => <TD key={k} className={cn("text-[13px]", typeof v === "number" && "num text-right")}>{v}</TD>)}</TR>
                  ))}
                </TBody>
              </Table>
            ) : (
              <CardContent className="text-sm text-muted">No records in period.</CardContent>
            )
          ) : null}
        </Card>
      ))}
    </div>
  );
}
