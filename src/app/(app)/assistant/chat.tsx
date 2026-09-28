"use client";
import { SendHorizonal } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { ActionError, useAction } from "@/components/soc/use-action";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label, Textarea } from "@/components/ui/input";
import { askAssistant } from "./actions";
import { ChatMessage, type ChatEntry } from "./message";

export function AssistantChat({
  tenantId,
  conversationId,
  initial,
  subject,
  disabled,
}: {
  tenantId: string;
  conversationId?: string;
  initial: ChatEntry[];
  subject?: { type: "alert" | "incident"; id: string };
  disabled?: boolean;
}) {
  const router = useRouter();
  const { pending, error, run } = useAction();
  const [messages, setMessages] = useState(initial);
  const [draft, setDraft] = useState(subject && !conversationId ? `Summarise this ${subject.type}: what happened, what evidence supports it, and what should I check next?` : "");
  const [allowWrites, setAllowWrites] = useState(false);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => end.current?.scrollIntoView({ block: "end" }), [messages.length, pending]);

  function send() {
    const message = draft.trim();
    if (!message || pending) return;
    setMessages((m) => [...m, { id: `local-${m.length}`, role: "user", content: message }]);
    setDraft("");
    run(
      () => askAssistant({ tenantId, message, conversationId, subject: conversationId ? undefined : subject, allowWrites }),
      (r) => {
        if (!r) return;
        setMessages((m) => [...m, { id: `reply-${m.length}`, role: "assistant", content: r.content, citations: r.citations, unverified: r.unverified, toolCalls: r.toolCalls, policy: r.policy }]);
        if (!conversationId) router.replace(`/assistant?tenant=${tenantId}&c=${r.conversationId}`, { scroll: false });
      },
    );
  }

  return (
    <div className="flex min-h-[60vh] flex-col">
      <div className="flex-1 space-y-3 p-4" aria-live="polite">
        {messages.length === 0 ? (
          <div className="py-10 text-center text-sm text-muted">
            Ask about alerts, incidents, assets, vulnerabilities or threat intel for this customer.
            <br />Answers cite the records they rely on.
          </div>
        ) : (
          messages.map((m) => <ChatMessage key={m.id} e={m} />)
        )}
        {pending ? <div className="animate-pulse text-xs text-muted">Retrieving evidence and drafting…</div> : null}
        <div ref={end} />
      </div>

      <form
        className="space-y-2 border-t border-border p-3"
        onSubmit={(e) => {
          e.preventDefault();
          send();
        }}
      >
        <Label htmlFor="assistant-input" className="sr-only">Message the AI analyst</Label>
        <Textarea
          id="assistant-input"
          value={draft}
          disabled={disabled}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
          placeholder={disabled ? "The AI analyst is unavailable for this customer." : "Ask a question. Enter to send, Shift+Enter for a new line."}
          className="min-h-16"
        />
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-start gap-2">
            <Checkbox id="allow-writes" checked={allowWrites} onCheckedChange={(v) => setAllowWrites(v === true)} disabled={disabled} className="mt-0.5" />
            <label htmlFor="allow-writes" className="text-xs text-muted">
              <span className="font-medium text-fg">Allow writes</span> — lets the analyst add AI-labelled case notes and <em>propose</em> containment. Proposals always go to human approval; nothing executes directly.
            </label>
          </div>
          <Button type="submit" size="sm" disabled={pending || disabled || !draft.trim()}>
            <SendHorizonal />{pending ? "Working…" : "Send"}
          </Button>
        </div>
        <ActionError error={error} />
      </form>
    </div>
  );
}
