export type ChatMessage =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string; toolCalls?: ToolCall[] }
  | { role: "tool"; toolCallId: string; name: string; content: string };

export type ToolCall = { id: string; name: string; args: Record<string, unknown> };

export type ToolSpec = { name: string; description: string; parameters: Record<string, unknown> };

export type ChatResult = { content: string; toolCalls: ToolCall[]; usage: { input: number; output: number } };

/** Where a provider processes data. Declared by the admin who registers it and enforced by policy. */
export type Residency = { region: string; country: "AU" | string; selfHosted: boolean };

export interface AIProvider {
  readonly id: string;
  readonly model: string;
  readonly residency: Residency;
  chat(messages: ChatMessage[], opts?: { tools?: ToolSpec[]; temperature?: number; maxTokens?: number }): Promise<ChatResult>;
  summarize(text: string, instruction?: string): Promise<string>;
  structuredOutput<T>(prompt: string, jsonSchema: Record<string, unknown>): Promise<T>;
  health(): Promise<{ ok: boolean; latencyMs: number; error?: string }>;
}

export abstract class BaseProvider implements AIProvider {
  abstract readonly id: string;
  abstract readonly model: string;
  abstract readonly residency: Residency;
  abstract chat(messages: ChatMessage[], opts?: { tools?: ToolSpec[]; temperature?: number; maxTokens?: number }): Promise<ChatResult>;

  async summarize(text: string, instruction = "Summarise for a SOC analyst. Facts only; say what is unknown.") {
    const r = await this.chat([{ role: "system", content: instruction }, { role: "user", content: text }], { temperature: 0.1 });
    return r.content;
  }

  async structuredOutput<T>(prompt: string, jsonSchema: Record<string, unknown>): Promise<T> {
    const r = await this.chat(
      [
        { role: "system", content: `Respond with a single JSON object matching this JSON Schema, and nothing else:\n${JSON.stringify(jsonSchema)}` },
        { role: "user", content: prompt },
      ],
      { temperature: 0 },
    );
    const json = r.content.slice(r.content.indexOf("{"), r.content.lastIndexOf("}") + 1);
    return JSON.parse(json) as T;
  }

  async health() {
    const start = Date.now();
    try {
      await this.chat([{ role: "user", content: "ping" }], { maxTokens: 5 });
      return { ok: true, latencyMs: Date.now() - start };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - start, error: (err as Error).message };
    }
  }
}
