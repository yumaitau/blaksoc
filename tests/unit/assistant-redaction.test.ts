import { describe, expect, it } from "vitest";
import { modelMessages } from "@/lib/ai/assistant";
import { redactPii } from "@/lib/ai/policy";

describe("assistant message assembly", () => {
  it("redacts earlier turns as well as the newest message", () => {
    const history = [
      { role: "user" as const, content: "Is jane.citizen@example.com.au the account in alert 12?" },
      { role: "assistant" as const, content: "Yes. Her mobile 0412 345 678 is on file." },
    ];
    const messages = modelMessages("system", history, "Email jane.citizen@example.com.au now", redactPii);
    const sent = messages.map((m) => m.content).join("\n");
    expect(sent).not.toMatch(/jane\.citizen/);
    expect(sent).not.toMatch(/0412 345 678/);
    expect(messages).toHaveLength(4);
    expect(messages[0]).toEqual({ role: "system", content: "system" });
  });
});
