import net from "node:net";
import { describe, expect, it } from "vitest";
import { messageMediaSmsRequest, twilioVoiceRequest } from "@/lib/connectors/au-notify";
import { connectorDef, type ConnectorInstance } from "@/lib/connectors/registry";
import type { Notifier, Notification } from "@/lib/connectors/notify";
import { decideEscalation, type EscalationStep } from "@/lib/portal/escalation";
import { incidentSentences } from "@/lib/portal/summary";

function notifyProvider(inst: ConnectorInstance): Notifier {
  if (inst.kind !== "notify") throw new Error(`expected notify, got ${inst.kind}`);
  return inst.provider;
}

const note = (to: string): Notification => ({
  event: "incident.created",
  tenant: { id: "t", name: "Wattle" },
  title: "Mailbox misuse",
  url: "http://localhost/portal/incidents/x",
  summary: "What happened: a mailbox.",
  to,
});

const step = (over: Partial<EscalationStep> = {}): EscalationStep => ({
  severity: "high",
  channel: "sms",
  contacts: ["+61400111000"],
  minIntervalMs: 60_000,
  maxAttempts: 2,
  ...over,
});

describe("incident sentences", () => {
  it("returns what happened, what we did, and what you need to do", () => {
    const [happened, did, need] = incidentSentences({
      title: "Mailbox misuse",
      severity: "high",
      status: "OPEN",
      actions: ["disabled a user account"],
    });
    const sentences = [happened, did, need];
    expect(sentences).toHaveLength(3);
    expect(sentences.every((s) => s.endsWith("."))).toBe(true);
    expect(happened).toContain("What happened:");
    expect(happened).toContain("Mailbox misuse");
    expect(did).toContain("disabled a user account");
    expect(need).toContain("I've read this");
  });
});

describe("escalation decisions", () => {
  const base = { steps: [step()], severity: "high", acknowledged: false, now: 1_000_000 };

  it("stops when the customer has acknowledged, even before any send", () => {
    expect(decideEscalation({ ...base, acknowledged: true, attempts: [] })).toEqual({ action: "stop", reason: "acknowledged" });
  });

  it("sends the first contact, then waits out the rate limit, then moves on", () => {
    expect(decideEscalation({ ...base, attempts: [] }).action).toBe("send");
    const first = decideEscalation({ ...base, attempts: [] });
    expect(first).toMatchObject({ action: "send", contact: "+61400111000", attempt: 1 });

    const waited = decideEscalation({
      ...base,
      now: 1_010_000,
      attempts: [{ at: 1_000_000, channel: "sms", contact: "+61400111000", status: "sent" }],
    });
    expect(waited).toEqual({ action: "wait", reason: "rate_limited", retryAt: 1_060_000 });

    const second = decideEscalation({
      ...base,
      now: 1_060_000,
      steps: [step({ contacts: ["+61400111000", "+61400222000"], maxAttempts: 1 })],
      attempts: [{ at: 1_000_000, channel: "sms", contact: "+61400111000", status: "sent" }],
    });
    expect(second).toMatchObject({ action: "send", contact: "+61400222000", attempt: 1 });
  });

  it("moves from SMS to voice only after the SMS contacts are exhausted", () => {
    const steps = [step({ maxAttempts: 1 }), step({ channel: "voice", contacts: ["+61400333000"], maxAttempts: 1 })];
    const next = decideEscalation({
      steps,
      severity: "high",
      acknowledged: false,
      now: 2_000_000,
      attempts: [{ at: 1_000_000, channel: "sms", contact: "+61400111000", status: "sent" }],
    });
    expect(next).toMatchObject({ action: "send", channel: "voice", contact: "+61400333000" });
  });

  it("stops when every contact has used its attempts", () => {
    const decision = decideEscalation({
      ...base,
      now: 9_000_000,
      attempts: [
        { at: 1_000_000, channel: "sms", contact: "+61400111000", status: "sent" },
        { at: 2_000_000, channel: "sms", contact: "+61400111000", status: "failed" },
      ],
    });
    expect(decision).toEqual({ action: "stop", reason: "exhausted" });
  });

  it("ignores a policy for a different severity", () => {
    expect(decideEscalation({ ...base, severity: "low", attempts: [] })).toEqual({ action: "stop", reason: "no_policy" });
  });
});

describe("Australian notify connectors", () => {
  it("registers SMS, voice, and email as available notify connectors", () => {
    for (const provider of ["sms", "voice", "email"]) {
      const def = connectorDef(provider);
      expect(def?.status).toBe("available");
      expect(def?.capabilities).toContain("notify");
      expect(def?.create).toBeTypeOf("function");
    }
  });

  it("builds a MessageMedia SMS request and a Twilio AU voice request without sending", () => {
    const sms = messageMediaSmsRequest({ from: "+61400111000", to: "+61400999888", body: "hello", apiKey: "fixture-key", apiSecret: "fixture-secret" });
    expect(new URL(sms.url).host).toBe("api.messagemedia.com");
    expect(JSON.parse(sms.body).messages[0]).toMatchObject({
      destination_number: "+61400999888",
      source_number: "+61400111000",
      format: "SMS",
    });

    const voice = twilioVoiceRequest({ accountSid: "ACfixture", authToken: "fixture-token", from: "+61400111000", to: "+61400999888", say: "Please read the portal." });
    expect(new URL(voice.url).host).toBe("api.twilio.com");
    expect(voice.url).toContain("/Calls.json");
    const params = new URLSearchParams(voice.body);
    expect(params.get("To")).toBe("+61400999888");
    expect(params.get("From")).toBe("+61400111000");
    expect(params.get("Twiml")).toContain('language="en-AU"');
  });

  it("records fixture SMS and voice delivery and refuses a non-AU number", async () => {
    const sms = connectorDef("sms")!;
    const smsInst = sms.create!(sms.config.parse({ from: "+61400111222", mode: "fixture" }), sms.secrets.parse({ apiKey: "k", apiSecret: "s" }));
    const smsNotify = notifyProvider(smsInst);
    await expect(smsNotify.deliver(note("+61400999888"))).resolves.toMatchObject({ status: "sent", providerRef: "fixture-sms" });
    await expect(smsNotify.deliver(note("+14155550100"))).resolves.toMatchObject({ status: "failed" });

    const voice = connectorDef("voice")!;
    const voiceInst = voice.create!(voice.config.parse({ from: "+61400111222", mode: "fixture" }), voice.secrets.parse({ accountSid: "ACfixture", authToken: "t" }));
    const voiceNotify = notifyProvider(voiceInst);
    await expect(voiceNotify.deliver(note("+61400999888"))).resolves.toMatchObject({ status: "sent", providerRef: "fixture-voice" });
  });

  it("sends email by speaking SMTP to a local relay", async () => {
    let captured = "";
    const server = net.createServer((socket) => {
      let mode: "cmd" | "data" = "cmd";
      let buf = "";
      socket.write("220 localhost ESMTP ready\r\n");
      socket.on("data", (chunk) => {
        buf += chunk.toString("utf8");
        if (mode === "data") {
          const end = buf.indexOf("\r\n.\r\n");
          if (end === -1) return;
          captured = buf.slice(0, end);
          buf = buf.slice(end + 5);
          mode = "cmd";
          socket.write("250 queued\r\n");
          return;
        }
        while (buf.includes("\r\n")) {
          const i = buf.indexOf("\r\n");
          const line = buf.slice(0, i);
          buf = buf.slice(i + 2);
          if (line.startsWith("EHLO")) socket.write("250 hello\r\n");
          else if (line.startsWith("AUTH")) socket.write("235 ok\r\n");
          else if (line.startsWith("MAIL FROM")) socket.write("250 ok\r\n");
          else if (line.startsWith("RCPT TO")) socket.write("250 ok\r\n");
          else if (line === "DATA") {
            mode = "data";
            socket.write("354 go\r\n");
          } else if (line.startsWith("QUIT")) socket.write("221 bye\r\n");
          else socket.write("500 unknown\r\n");
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as net.AddressInfo).port;
    try {
      const email = connectorDef("email")!;
      const live = email.create!(
        email.config.parse({ host: "127.0.0.1", port, from: "soc@example.com", mode: "live" }),
        email.secrets.parse({ username: "relay", password: "secret" }),
      );
      const liveNotify = notifyProvider(live);
      const receipt = await liveNotify.deliver({ ...note("ceo@example.com"), summary: "What happened: a mailbox." });
      expect(receipt.status).toBe("sent");
      expect(captured).toContain("Subject: Mailbox misuse");
      expect(captured).toContain("To: ceo@example.com");
      expect(captured).toContain("What happened: a mailbox.");

      const fixture = email.create!(
        email.config.parse({ host: "127.0.0.1", port: 1, from: "soc@example.com", mode: "fixture" }),
        email.secrets.parse({ username: "relay", password: "secret" }),
      );
      await expect(notifyProvider(fixture).deliver(note("ceo@example.com"))).resolves.toMatchObject({ status: "sent", providerRef: "fixture-email" });
    } finally {
      server.close();
    }
  });
});
