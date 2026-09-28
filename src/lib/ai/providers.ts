import { BedrockRuntimeClient, ConverseCommand, type ContentBlock, type Message, type Tool } from "@aws-sdk/client-bedrock-runtime";
import { BaseProvider, type ChatMessage, type ChatResult, type Residency, type ToolSpec } from "./types";

/**
 * OpenAI-compatible Chat Completions. Covers OpenAI, Azure OpenAI (deployment + api-version),
 * local Ollama (/v1) and vLLM (/v1) — the sovereign self-hosted options.
 */
export class OpenAICompatibleProvider extends BaseProvider {
  constructor(
    readonly id: string,
    private readonly cfg: { baseUrl: string; model: string; apiKey?: string; azureApiVersion?: string; residency: Residency },
  ) {
    super();
  }
  get model() {
    return this.cfg.model;
  }
  get residency() {
    return this.cfg.residency;
  }

  async chat(messages: ChatMessage[], opts: { tools?: ToolSpec[]; temperature?: number; maxTokens?: number } = {}): Promise<ChatResult> {
    const azure = !!this.cfg.azureApiVersion;
    const url = azure
      ? `${this.cfg.baseUrl.replace(/\/$/, "")}/openai/deployments/${this.cfg.model}/chat/completions?api-version=${this.cfg.azureApiVersion}`
      : `${this.cfg.baseUrl.replace(/\/$/, "")}/chat/completions`;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.cfg.apiKey) headers[azure ? "api-key" : "authorization"] = azure ? this.cfg.apiKey : `Bearer ${this.cfg.apiKey}`;
    const body = {
      ...(azure ? {} : { model: this.cfg.model }),
      temperature: opts.temperature ?? 0.2,
      max_tokens: opts.maxTokens ?? 1500,
      messages: messages.map((m) =>
        m.role === "tool"
          ? { role: "tool", tool_call_id: m.toolCallId, content: m.content }
          : m.role === "assistant" && m.toolCalls?.length
            ? { role: "assistant", content: m.content || null, tool_calls: m.toolCalls.map((t) => ({ id: t.id, type: "function", function: { name: t.name, arguments: JSON.stringify(t.args) } })) }
            : { role: m.role, content: m.content },
      ),
      ...(opts.tools?.length ? { tools: opts.tools.map((t) => ({ type: "function", function: t })), tool_choice: "auto" } : {}),
    };
    const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body), signal: AbortSignal.timeout(120_000) });
    if (!res.ok) throw new Error(`${this.id}: ${res.status} ${(await res.text()).slice(0, 300)}`);
    const data = (await res.json()) as {
      choices: { message: { content: string | null; tool_calls?: { id: string; function: { name: string; arguments: string } }[] } }[];
      usage?: { prompt_tokens: number; completion_tokens: number };
    };
    const msg = data.choices[0]!.message;
    return {
      content: msg.content ?? "",
      toolCalls: (msg.tool_calls ?? []).map((t) => ({ id: t.id, name: t.function.name, args: safeJson(t.function.arguments) })),
      usage: { input: data.usage?.prompt_tokens ?? 0, output: data.usage?.completion_tokens ?? 0 },
    };
  }
}

/** Amazon Bedrock Converse API. Pin region to ap-southeast-2 (Sydney) / ap-southeast-4 (Melbourne) for AU residency. */
export class BedrockProvider extends BaseProvider {
  private readonly client: BedrockRuntimeClient;
  constructor(readonly id: string, private readonly cfg: { region: string; model: string; accessKeyId?: string; secretAccessKey?: string }) {
    super();
    this.client = new BedrockRuntimeClient({
      region: cfg.region,
      ...(cfg.accessKeyId && cfg.secretAccessKey ? { credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey } } : {}),
    });
  }
  get model() {
    return this.cfg.model;
  }
  get residency(): Residency {
    return { region: this.cfg.region, country: /^ap-southeast-(2|4)$/.test(this.cfg.region) ? "AU" : this.cfg.region, selfHosted: false };
  }

  async chat(messages: ChatMessage[], opts: { tools?: ToolSpec[]; temperature?: number; maxTokens?: number } = {}): Promise<ChatResult> {
    const system = messages.filter((m) => m.role === "system").map((m) => ({ text: m.content }));
    const conv: Message[] = [];
    for (const m of messages) {
      if (m.role === "system") continue;
      if (m.role === "tool") {
        const block: ContentBlock = { toolResult: { toolUseId: m.toolCallId, content: [{ text: m.content }] } };
        const last = conv.at(-1);
        if (last?.role === "user" && last.content?.every((c) => "toolResult" in c)) last.content.push(block);
        else conv.push({ role: "user", content: [block] });
      } else if (m.role === "assistant") {
        const content: ContentBlock[] = [];
        if (m.content) content.push({ text: m.content });
        for (const t of m.toolCalls ?? []) content.push({ toolUse: { toolUseId: t.id, name: t.name, input: t.args as never } });
        conv.push({ role: "assistant", content });
      } else conv.push({ role: "user", content: [{ text: m.content }] });
    }
    const out = await this.client.send(
      new ConverseCommand({
        modelId: this.cfg.model,
        system,
        messages: conv,
        inferenceConfig: { temperature: opts.temperature ?? 0.2, maxTokens: opts.maxTokens ?? 1500 },
        ...(opts.tools?.length ? { toolConfig: { tools: opts.tools.map((t): Tool => ({ toolSpec: { name: t.name, description: t.description, inputSchema: { json: t.parameters as never } } })) } } : {}),
      }),
    );
    const blocks = out.output?.message?.content ?? [];
    return {
      content: blocks.map((b) => ("text" in b ? b.text : "")).join(""),
      toolCalls: blocks.filter((b) => "toolUse" in b && b.toolUse).map((b) => ({ id: b.toolUse!.toolUseId!, name: b.toolUse!.name!, args: (b.toolUse!.input ?? {}) as Record<string, unknown> })),
      usage: { input: out.usage?.inputTokens ?? 0, output: out.usage?.outputTokens ?? 0 },
    };
  }
}

function safeJson(s: string): Record<string, unknown> {
  try {
    return JSON.parse(s) as Record<string, unknown>;
  } catch {
    return {};
  }
}
