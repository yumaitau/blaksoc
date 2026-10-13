import "server-only";
import { sanitizeIntelHtml } from "@/lib/intel/html";
import { cn } from "@/lib/utils";

/** Sanitize at the rendering boundary so old and newly fetched intel get the same policy. */
export function IntelHtml({ content, className }: { content: string; className?: string }) {
  return <div className={cn(
    "max-h-64 overflow-auto break-words text-xs text-muted [&_p]:my-2 [&_ul]:list-disc [&_ol]:list-decimal [&_ul]:pl-5 [&_ol]:pl-5 [&_li]:my-1 [&_a]:text-accent [&_a]:underline [&_h2]:font-semibold [&_h3]:font-semibold [&_h4]:font-semibold [&_blockquote]:border-l-2 [&_blockquote]:border-border [&_blockquote]:pl-3 [&_pre]:whitespace-pre-wrap [&_pre]:rounded [&_pre]:bg-surface-2 [&_pre]:p-2 [&_code]:font-mono [&_table]:w-full [&_th]:border [&_th]:border-border [&_th]:p-2 [&_td]:border [&_td]:border-border [&_td]:p-2",
    className,
  )} dangerouslySetInnerHTML={{ __html: sanitizeIntelHtml(content) }} />;
}
