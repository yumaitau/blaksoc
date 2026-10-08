import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { SocTool, ToolState } from "@/lib/services/soc-tools";
import { timeAgo } from "@/lib/utils";

const STATE: Record<ToolState, { label: string; variant: "ok" | "warn" | "danger" | "outline" }> = {
  ok: { label: "Operational", variant: "ok" },
  degraded: { label: "Degraded", variant: "warn" },
  down: { label: "Down", variant: "danger" },
  unknown: { label: "Unknown", variant: "outline" },
};

/** Companion tools with their status and a link out. Status comes from the last health check, never a guess. */
export function ToolCards({ tools }: { tools: SocTool[] }) {
  return (
    <section aria-label="Security tools" className="grid gap-3 md:grid-cols-3">
      {tools.map((t) => {
        const s = STATE[t.state];
        return (
          <Card key={t.key}>
            <CardHeader>
              <div className="min-w-0">
                <CardTitle>{t.name}</CardTitle>
                <div className="truncate text-xs text-muted">{t.role}</div>
              </div>
              <Badge variant={s.variant}>{s.label}</Badge>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className={t.state === "down" ? "break-words text-sm text-danger" : "break-words text-sm"} title={t.summary}>{t.summary}</p>
              <div className="flex items-center justify-between gap-3 text-xs">
                <span className="text-faint">{t.checkedAt ? `Checked ${timeAgo(t.checkedAt)}` : "Not checked"}</span>
                {t.url ? (
                  <a href={t.url} target="_blank" rel="noreferrer" className="font-medium text-accent hover:underline">Open {t.name} ↗</a>
                ) : (
                  <span className="text-faint">No link configured</span>
                )}
              </div>
            </CardContent>
          </Card>
        );
      })}
    </section>
  );
}
