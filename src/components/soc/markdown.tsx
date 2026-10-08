import { Fragment } from "react";

/**
 * Minimal markdown for machine-written reports: headings, lists, fenced code, tables (as preformatted text),
 * paragraphs, `code`, **bold** and *emphasis*. Builds React elements only (no HTML injection) and renders
 * links as text, so a report can never navigate or load anything.
 */
export function Markdown({ text }: { text: string }) {
  return <div className="space-y-2 text-sm leading-relaxed">{blocks(text)}</div>;
}

function inline(s: string, key: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  const re = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*|\[[^\]]+\]\([^)\s]+\))/g;
  let last = 0;
  let i = 0;
  for (const m of s.matchAll(re)) {
    out.push(s.slice(last, m.index));
    const t = m[0];
    const k = `${key}-${i++}`;
    if (t.startsWith("`")) out.push(<code key={k} className="rounded bg-surface-2 px-1 font-mono text-[12px]">{t.slice(1, -1)}</code>);
    else if (t.startsWith("**")) out.push(<strong key={k}>{t.slice(2, -2)}</strong>);
    else if (t.startsWith("[")) {
      const [, label, url] = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(t)!;
      out.push(<Fragment key={k}>{label} <span className="text-faint">({url})</span></Fragment>);
    } else out.push(<em key={k}>{t.slice(1, -1)}</em>);
    last = m.index + t.length;
  }
  out.push(s.slice(last));
  return out;
}

function blocks(text: string): React.ReactNode[] {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const out: React.ReactNode[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    const k = `b${i}`;
    if (/^```/.test(line)) {
      const body: string[] = [];
      for (i++; i < lines.length && !/^```/.test(lines[i]!); i++) body.push(lines[i]!);
      i++;
      out.push(<pre key={k} className="overflow-x-auto rounded-md bg-bg p-3 font-mono text-[12px] text-muted">{body.join("\n")}</pre>);
      continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) {
      const cls = h[1]!.length <= 1 ? "text-base font-semibold" : h[1]!.length === 2 ? "text-[15px] font-semibold" : "text-sm font-semibold";
      out.push(<div key={k} role="heading" aria-level={Math.min(6, h[1]!.length + 1)} className={`pt-1 ${cls}`}>{inline(h[2]!, k)}</div>);
      i++;
      continue;
    }
    if (/^\s*\|/.test(line)) {
      const body: string[] = [];
      for (; i < lines.length && /^\s*\|/.test(lines[i]!); i++) body.push(lines[i]!);
      out.push(<pre key={k} className="overflow-x-auto font-mono text-[12px]">{body.join("\n")}</pre>);
      continue;
    }
    if (/^\s*([-*+]|\d+[.)])\s+/.test(line)) {
      const ordered = /^\s*\d/.test(line);
      const items: string[] = [];
      for (; i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i]!); i++) items.push(lines[i]!.replace(/^\s*([-*+]|\d+[.)])\s+/, ""));
      const List = ordered ? "ol" : "ul";
      out.push(<List key={k} className={`${ordered ? "list-decimal" : "list-disc"} space-y-0.5 pl-5`}>{items.map((it, j) => <li key={j}>{inline(it, `${k}-${j}`)}</li>)}</List>);
      continue;
    }
    if (!line.trim()) {
      i++;
      continue;
    }
    const para: string[] = [];
    for (; i < lines.length && lines[i]!.trim() && !/^(```|#{1,4}\s|\s*\||\s*([-*+]|\d+[.)])\s+)/.test(lines[i]!); i++) para.push(lines[i]!);
    out.push(<p key={k}>{inline(para.join(" "), k)}</p>);
  }
  return out;
}
