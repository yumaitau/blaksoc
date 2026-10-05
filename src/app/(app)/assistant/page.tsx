import { Info, ShieldOff } from "lucide-react";
import Link from "next/link";
import { EmptyState, PageHeader } from "@/components/soc/indicators";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { aiProviderFor, conversationMessages, governedAiDecision, listConversations } from "@/lib/ai/assistant";
import { governanceFor } from "@/lib/services/governance";
import { can } from "@/lib/auth/access";
import { requireAccess } from "@/lib/auth/session";
import { env } from "@/lib/env";
import { listTenants } from "@/lib/services/admin";
import { getAlert } from "@/lib/services/alerts";
import { getIncident } from "@/lib/services/incidents";
import { cn, timeAgo } from "@/lib/utils";
import { currentWorkspace } from "@/lib/workspace";
import { AssistantChat } from "./chat";
import type { ChatEntry } from "./message";
import { TenantPicker } from "./tenant-picker";

export const metadata = { title: "AI analyst" };

type Search = { tenant?: string; c?: string; alert?: string; incident?: string };
const UUID = /^[0-9a-f-]{36}$/i;

/** Resolve ?alert= / ?incident= to a subject and its tenant, through the RBAC-scoped services. */
async function resolveSubject(ctx: Awaited<ReturnType<typeof requireAccess>>, sp: Search) {
  try {
    if (sp.alert && UUID.test(sp.alert)) {
      const a = await getAlert(ctx, sp.alert);
      if (a) return { type: "alert" as const, id: a.alert.id, tenantId: a.alert.tenantId, label: a.alert.title };
    }
    if (sp.incident && UUID.test(sp.incident)) {
      const i = await getIncident(ctx, sp.incident);
      if (i) return { type: "incident" as const, id: i.incident.id, tenantId: i.incident.tenantId, label: `INC-${i.incident.ref} · ${i.incident.title}` };
    }
  } catch {
    // No read access to the subject: fall through to an unscoped conversation.
  }
  return null;
}

export default async function AssistantPage({ searchParams }: { searchParams: Promise<Search> }) {
  const ctx = await requireAccess();
  const sp = await searchParams;
  const aiTenants = ctx.tenants.filter((t) => can(ctx, "ai:use", t.id));
  if (!aiTenants.length) {
    return (
      <>
        <PageHeader eyebrow="Investigate" title="AI SOC analyst" />
        <EmptyState title="AI analyst not available">Your role does not include AI assistance for any customer.</EmptyState>
      </>
    );
  }

  const subject = await resolveSubject(ctx, sp);
  const ws = await currentWorkspace(ctx);
  const pick = (id?: string | null) => (id && aiTenants.some((t) => t.id === id) ? id : undefined);
  const tenantId = pick(subject?.tenantId) ?? pick(sp.tenant) ?? pick(ws.tenant?.id) ?? (aiTenants.find((t) => t.kind === "customer") ?? aiTenants[0]!).id;

  const [conversations, tenantRows, provider, profile] = await Promise.all([listConversations(ctx, tenantId), listTenants(ctx), aiProviderFor(tenantId), governanceFor(tenantId)]);
  const settings = tenantRows.find((t) => t.id === tenantId)?.settings;
  const decision = provider && settings ? governedAiDecision(settings.ai, profile, provider) : null;
  const conversation = sp.c ? conversations.find((c) => c.id === sp.c) : undefined;
  const rows = conversation ? await conversationMessages(ctx, tenantId, conversation.id) : [];
  const initial: ChatEntry[] = rows
    .filter((m) => m.role === "user" || m.role === "assistant")
    .map((m) => ({ id: m.id, role: m.role as "user" | "assistant", content: m.content, citations: m.citations ?? undefined, unverified: m.unverifiedCitations ?? undefined, toolCalls: m.toolCalls?.map(({ name, args }) => ({ name, args })) ?? undefined }));
  const chatSubject = conversation?.subject ?? (subject ? { type: subject.type, id: subject.id } : undefined);
  const unavailable = !provider || (decision !== null && !decision.allowed);

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Investigate"
        title="AI SOC analyst"
        description="Retrieves evidence with your permissions and cites every record it relies on. AI output is interpretation, not evidence."
        actions={<TenantPicker tenants={aiTenants.map((t) => ({ id: t.id, name: t.name }))} value={tenantId} />}
      />

      {!provider ? (
        <div role="status" className="flex items-start gap-3 rounded-lg border border-warn/40 bg-warn/10 px-4 py-3 text-sm">
          <ShieldOff className="mt-0.5 size-4 shrink-0 text-warn" />
          <div>
            <div className="font-medium text-warn">No AI provider is configured for this customer.</div>
            <div className="text-muted">
              A platform administrator can add one. A self-hosted model keeps data onshore:{" "}
              <Link href="/integrations/new?provider=ollama" className="text-accent hover:underline">add an Ollama provider</Link>.
            </div>
          </div>
        </div>
      ) : decision && !decision.allowed ? (
        <div role="status" className="flex items-start gap-3 rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm">
          <ShieldOff className="mt-0.5 size-4 shrink-0 text-danger" />
          <div>
            <div className="font-medium text-danger">Blocked by AI policy</div>
            <div className="text-muted">{decision.reason}. Change the customer&apos;s AI policy under Administration, or register an approved provider.</div>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-border bg-surface px-4 py-2 text-xs text-muted">
          <span className="flex items-center gap-1.5"><Info className="size-3.5" />Provider: <span className="text-fg">{decision?.reason}</span></span>
          <span>Residency policy: {env().AI_DATA_RESIDENCY === "AU" ? "Australia only" : "any region"}</span>
          {settings ? <span>PII redaction {settings.ai.redactPii ? "on" : "off"} · raw events {settings.ai.allowRawEvents ? "allowed" : "withheld"}</span> : null}
          <Badge variant="warn" className="ml-auto">AI output is interpretation, not evidence</Badge>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[16rem_1fr]">
        <Card className="self-start">
          <CardHeader>
            <CardTitle>Conversations</CardTitle>
            <Link href={`/assistant?tenant=${tenantId}`} className="text-xs text-accent hover:underline">New</Link>
          </CardHeader>
          <nav aria-label="Conversations" className="max-h-[65vh] divide-y divide-border overflow-y-auto">
            {conversations.length === 0 ? (
              <div className="p-4 text-xs text-muted">No conversations for this customer yet.</div>
            ) : (
              [...conversations].reverse().map((c) => (
                <Link
                  key={c.id}
                  href={`/assistant?tenant=${tenantId}&c=${c.id}`}
                  aria-current={c.id === conversation?.id ? "page" : undefined}
                  className={cn("block px-4 py-2 hover:bg-surface-2/60", c.id === conversation?.id && "bg-surface-2")}
                >
                  <div className="truncate text-sm">{c.title}</div>
                  <div className="text-[11px] text-faint">{c.subject ? `${c.subject.type} · ` : ""}{timeAgo(c.createdAt)}</div>
                </Link>
              ))
            )}
          </nav>
        </Card>

        <Card className="min-w-0">
          <CardHeader>
            <CardTitle className="truncate">{conversation?.title ?? "New conversation"}</CardTitle>
            {chatSubject ? (
              <span className="text-xs text-muted">
                Subject: {subject && subject.id === chatSubject.id ? subject.label : `${chatSubject.type} ${chatSubject.id.slice(0, 8)}…`}
              </span>
            ) : null}
          </CardHeader>
          <AssistantChat
            key={`${tenantId}:${conversation?.id ?? "new"}`}
            tenantId={tenantId}
            conversationId={conversation?.id}
            initial={initial}
            subject={chatSubject && (chatSubject.type === "alert" || chatSubject.type === "incident") ? { type: chatSubject.type, id: chatSubject.id } : undefined}
            disabled={unavailable}
          />
        </Card>
      </div>
    </div>
  );
}
