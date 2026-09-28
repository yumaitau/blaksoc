import { AlertTriangle, ChevronRight, Wrench } from "lucide-react";
import { RefLink } from "@/components/soc/indicators";
import { cn } from "@/lib/utils";

export type ChatEntry = {
  id: string;
  role: "user" | "assistant";
  content: string;
  citations?: { type: string; id: string; label: string }[];
  unverified?: string[];
  toolCalls?: { name: string; args: unknown }[];
  policy?: string;
};

const CITE = /\[\[([a-z]+):([^\]\s]+)\]\]/g;

/** Inline [[type:id]] citations become record links; anything no tool returned is flagged, not linked. */
function withCitations(text: string, e: ChatEntry) {
  const out: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(CITE)) {
    out.push(text.slice(last, m.index));
    const key = `${m[1]}:${m[2]}`;
    if (e.unverified?.includes(key)) {
      out.push(
        <span key={m.index} title="The model cited something no tool returned. Treat as unsupported." className="rounded bg-warn/15 px-1 font-mono text-[12px] text-warn line-through decoration-warn/60">
          {key}
        </span>,
      );
    } else {
      out.push(<span key={m.index} className="font-mono text-[12px]">[<RefLink type={m[1]!} id={m[2]!} />]</span>);
    }
    last = m.index + m[0].length;
  }
  out.push(text.slice(last));
  return out;
}

export function ChatMessage({ e }: { e: ChatEntry }) {
  if (e.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[80%] whitespace-pre-wrap rounded-lg bg-accent-soft px-3.5 py-2 text-sm text-fg">{e.content}</div>
      </div>
    );
  }
  return (
    <div className="space-y-2 rounded-lg border border-border bg-surface px-4 py-3">
      <div className="flex items-center justify-between gap-2 text-[11px] uppercase tracking-wider">
        <span className="font-semibold text-warn">AI analyst · interpretation</span>
        {e.policy ? <span className="normal-case tracking-normal text-faint">via {e.policy}</span> : null}
      </div>
      <div className="whitespace-pre-wrap text-sm leading-relaxed">{withCitations(e.content, e)}</div>

      {e.unverified?.length ? (
        <div role="note" className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 text-xs text-warn">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
          <div>
            <div className="font-semibold">Unverified citations: {e.unverified.join(", ")}</div>
            <div>The model cited something no tool returned. Treat those statements as unsupported.</div>
          </div>
        </div>
      ) : null}

      {e.citations?.length ? (
        <div className="text-xs">
          <div className="mb-1 font-medium text-muted">Verified evidence ({e.citations.length})</div>
          <ul className="flex flex-wrap gap-x-3 gap-y-1">
            {e.citations.map((c) => (
              <li key={`${c.type}:${c.id}`} className="max-w-full truncate"><RefLink type={c.type} id={c.id} label={`${c.type}: ${c.label}`} /></li>
            ))}
          </ul>
        </div>
      ) : null}

      {e.toolCalls?.length ? (
        <details className="group text-xs">
          <summary className="flex cursor-pointer list-none items-center gap-1 text-muted hover:text-fg">
            <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" />
            <Wrench className="size-3.5" />
            {e.toolCalls.length} tool call{e.toolCalls.length === 1 ? "" : "s"}
          </summary>
          <ol className="mt-1.5 space-y-1 pl-5">
            {e.toolCalls.map((t, i) => (
              <li key={i} className={cn("font-mono text-[11px]", ["create_case_note", "propose_response_action"].includes(t.name) ? "text-warn" : "text-muted")}>
                {t.name}({JSON.stringify(t.args)})
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </div>
  );
}
