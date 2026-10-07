import { and, asc, eq, isNull, or } from "drizzle-orm";
import { systemDb } from "@/db/client";
import { aiConversations, aiInvocations, aiMessages, integrations, tenants, type AiPolicy, type Citation, type GovernanceProfile } from "@/db/schema";
import { withScope } from "@/db/scope";
import { assertCan, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { instantiate } from "@/lib/connectors/instances";
import { env } from "@/lib/env";
import { checkGovernedAi } from "@/lib/governance/policy";
import { governanceProfile } from "@/lib/services/governance";
import { aiCalls } from "@/lib/obs/metrics";
import { checkAiPolicy, redactPii, type PolicyDecision } from "./policy";
import { toolsFor, type ToolContext } from "./tools";
import type { AIProvider, ChatMessage } from "./types";

const SYSTEM = `You are the blakSOC AI SOC Analyst, an accelerator for human analysts at an Australian MSSP.
You are NOT an autonomous security authority.

Rules:
- Use tools to retrieve evidence. Never invent alerts, assets, indicators, actors or ATT&CK mappings.
- Every factual assertion must cite its evidence inline as [[type:id]] using ids returned by tools
  (types: alert, asset, incident, opencti, cve, attack, rule). If you have no evidence, say so.
- Clearly separate "Evidence" (what the records show) from "Assessment" (your interpretation) and "Suggested next steps".
- Risk scores come from the blakSOC risk engine; explain their factors, never re-score.
- You cannot execute containment. You may only propose actions, which wait for human approval.
- Be concise. Use Australian English.`;

const CITE = /\[\[(alert|asset|incident|opencti|cve|attack|rule):([^\]\s]+)\]\]/g;

export async function aiProviderFor(tenantId: string): Promise<AIProvider | null> {
  // AI provider integrations are platform or tenant owned; read with owner connection, then policy-check.
  const rows = await systemDb().select().from(integrations).where(and(eq(integrations.category, "ai"), eq(integrations.enabled, true), or(eq(integrations.tenantId, tenantId), isNull(integrations.tenantId))));
  const row = rows.sort((a, b) => (b.tenantId ? 1 : 0) - (a.tenantId ? 1 : 0))[0];
  if (!row) return null;
  const inst = instantiate(row);
  return inst.kind === "ai" ? inst.provider : null;
}

/** Tenant AI settings, platform residency, and the steward governance profile must all allow the call. */
export function governedAiDecision(settings: AiPolicy, profile: GovernanceProfile, provider: AIProvider): PolicyDecision {
  const base = checkAiPolicy(settings, provider, env().AI_DATA_RESIDENCY);
  if (!base.allowed) return base;
  const governed = checkGovernedAi(profile, "assistant", provider);
  return governed.allowed ? base : governed;
}

export type AssistantReply = {
  conversationId: string;
  content: string;
  citations: Citation[];
  unverified: string[];
  toolCalls: { name: string; args: unknown }[];
  policy: string;
};

/** What the model receives. Earlier turns are stored as typed, so they are redacted on every send, not only the newest message. */
export function modelMessages(system: string, history: ChatMessage[], message: string, scrub: (s: string) => string): ChatMessage[] {
  return [{ role: "system", content: system }, ...history.map((m) => ({ ...m, content: scrub(m.content) })), { role: "user", content: scrub(message) }];
}

export async function runAssistant(ctx: AccessContext, input: { tenantId: string; message: string; conversationId?: string; subject?: { type: string; id: string }; allowWrites?: boolean }): Promise<AssistantReply> {
  assertCan(ctx, "ai:use", input.tenantId);
  const scope = { tenantIds: [input.tenantId], platform: false };
  const [tenant] = await withScope(scope, (tx) => tx.select().from(tenants).where(eq(tenants.id, input.tenantId)));
  if (!tenant) throw new Error("tenant not found");

  const provider = await aiProviderFor(input.tenantId);
  if (!provider) throw new Error("No AI provider is configured. A platform administrator can add one under Integrations → AI.");
  const profile = await withScope(scope, (tx) => governanceProfile(tx, input.tenantId));
  const decision = governedAiDecision(tenant.settings.ai, profile, provider);

  let conversationId = input.conversationId;
  const history: ChatMessage[] = [];
  await withScope(scope, async (tx) => {
    if (conversationId) {
      const [c] = await tx.select().from(aiConversations).where(and(eq(aiConversations.id, conversationId), eq(aiConversations.userId, ctx.principal.userId)));
      if (!c) throw new Error("conversation not found");
      const prior = await tx.select().from(aiMessages).where(eq(aiMessages.conversationId, conversationId)).orderBy(asc(aiMessages.createdAt));
      for (const m of prior.slice(-12)) if (m.role === "user" || m.role === "assistant") history.push({ role: m.role, content: m.content });
    } else {
      const [c] = await tx.insert(aiConversations).values({ tenantId: input.tenantId, userId: ctx.principal.userId, title: input.message.slice(0, 80), subject: input.subject ?? null }).returning();
      conversationId = c!.id;
    }
    await tx.insert(aiMessages).values({ tenantId: input.tenantId, conversationId: conversationId!, role: "user", content: input.message });
    await tx.insert(aiInvocations).values({ tenantId: input.tenantId, userId: ctx.principal.userId, provider: provider.id, model: provider.model, region: provider.residency.region, purpose: "assistant", policyDecision: decision.allowed ? "allowed" : `denied: ${decision.reason}` });
  });
  const aiLabels = { provider: provider.id, purpose: "assistant" };
  if (!decision.allowed) {
    aiCalls().inc({ ...aiLabels, outcome: "denied" });
    throw new Error(`AI policy blocked this request: ${decision.reason}`);
  }

  const scrub = (s: string) => (tenant.settings.ai.redactPii ? redactPii(s) : s);
  const toolCtx: ToolContext = { ctx, tenantId: input.tenantId, allowWrites: !!input.allowWrites };
  const tools = toolsFor(toolCtx.allowWrites);
  const retrieved = new Map<string, Citation>();
  const calls: { name: string; args: unknown; resultRefs: Citation[] }[] = [];

  const subjectHint = input.subject ? `\nThe analyst is looking at ${input.subject.type} ${input.subject.id}. Start by retrieving it.` : "";
  const messages = modelMessages(`${SYSTEM}\nTenant: ${tenant.name}. Writes ${toolCtx.allowWrites ? "enabled (notes, proposals)" : "disabled — read-only"}.${subjectHint}`, history, input.message, scrub);

  let final = "";
  let usageIn = 0, usageOut = 0;
  for (let turn = 0; turn < 6; turn++) {
    const res = await provider.chat(messages, { tools, temperature: 0.1 }).catch((err: unknown) => {
      aiCalls().inc({ ...aiLabels, outcome: "error" });
      throw err;
    });
    usageIn += res.usage.input;
    usageOut += res.usage.output;
    if (!res.toolCalls.length) {
      final = res.content;
      break;
    }
    messages.push({ role: "assistant", content: res.content, toolCalls: res.toolCalls });
    for (const call of res.toolCalls) {
      const tool = tools.find((t) => t.name === call.name);
      let content: string;
      let refs: Citation[] = [];
      if (!tool) content = `tool ${call.name} is not available${toolCtx.allowWrites ? "" : " (writes disabled)"}`;
      else {
        try {
          const out = await tool.run(call.args, toolCtx);
          refs = out.citations;
          refs.forEach((c) => retrieved.set(`${c.type}:${c.id}`, c));
          // Raw event payloads never reach the model unless the tenant allows it.
          content = scrub(JSON.stringify(out.data, (k, v) => (k === "raw" && !tenant.settings.ai.allowRawEvents ? undefined : v)).slice(0, 12_000));
        } catch (err) {
          content = `error: ${(err as Error).message}`;
        }
      }
      calls.push({ name: call.name, args: call.args, resultRefs: refs });
      messages.push({ role: "tool", toolCallId: call.id, name: call.name, content });
    }
  }
  if (!final) final = "I could not complete this within the tool-call budget. Try a narrower question.";

  // Verify citations: anything the model cites that no tool returned is flagged, not trusted.
  const cited: Citation[] = [];
  const unverified: string[] = [];
  for (const m of final.matchAll(CITE)) {
    const key = `${m[1]}:${m[2]}`;
    const c = retrieved.get(key);
    if (c) {
      if (!cited.some((x) => x.type === c.type && x.id === c.id)) cited.push(c);
    } else if (!unverified.includes(key)) unverified.push(key);
  }

  await withScope(scope, async (tx) => {
    await tx.insert(aiMessages).values({ tenantId: input.tenantId, conversationId: conversationId!, role: "assistant", content: final, toolCalls: calls, citations: cited, unverifiedCitations: unverified });
    await tx.insert(aiInvocations).values({ tenantId: input.tenantId, userId: ctx.principal.userId, provider: provider.id, model: provider.model, region: provider.residency.region, purpose: "assistant", policyDecision: "completed", inputTokens: usageIn, outputTokens: usageOut });
    const writes = calls.filter((c) => ["create_case_note", "propose_response_action"].includes(c.name));
    for (const w of writes) await audit(tx, { actorId: ctx.principal.userId, actorKind: "ai", tenantId: input.tenantId, action: `ai.${w.name}`, targetType: "ai_conversation", targetId: conversationId!, detail: { args: w.args } });
  });

  aiCalls().inc({ ...aiLabels, outcome: "completed" });
  return { conversationId: conversationId!, content: final, citations: cited, unverified, toolCalls: calls.map(({ name, args }) => ({ name, args })), policy: decision.reason };
}

export async function listConversations(ctx: AccessContext, tenantId: string) {
  assertCan(ctx, "ai:use", tenantId);
  return withScope({ tenantIds: [tenantId], platform: false }, (tx) =>
    tx.select().from(aiConversations).where(and(eq(aiConversations.tenantId, tenantId), eq(aiConversations.userId, ctx.principal.userId))).orderBy(asc(aiConversations.createdAt)).limit(50),
  );
}

export async function conversationMessages(ctx: AccessContext, tenantId: string, conversationId: string) {
  assertCan(ctx, "ai:use", tenantId);
  return withScope({ tenantIds: [tenantId], platform: false }, async (tx) => {
    const [c] = await tx.select().from(aiConversations).where(and(eq(aiConversations.id, conversationId), eq(aiConversations.userId, ctx.principal.userId)));
    if (!c) return [];
    return tx.select().from(aiMessages).where(eq(aiMessages.conversationId, conversationId)).orderBy(asc(aiMessages.createdAt));
  });
}
