import net from "node:net";
import type { DeliveryReceipt, Notification, Notifier } from "./notify";

export type VendorRequest = {
  url: string;
  method: "POST";
  headers: Record<string, string>;
  body: string;
};

const AU_NUMBER = /^\+61\d{8,10}$/;

export function isAuNumber(value: string): boolean {
  return AU_NUMBER.test(value);
}

function xmlEscape(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function basic(user: string, pass: string): string {
  return `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`;
}

/** MessageMedia SMS request for an Australian source number. Does not send. */
export function messageMediaSmsRequest(input: { from: string; to: string; body: string; apiKey: string; apiSecret: string }): VendorRequest {
  return {
    url: "https://api.messagemedia.com/v1/messages",
    method: "POST",
    headers: {
      authorization: basic(input.apiKey, input.apiSecret),
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({
      messages: [{ content: input.body, destination_number: input.to, source_number: input.from, format: "SMS" }],
    }),
  };
}

/** Twilio voice request. TwiML is spoken in Australian English. Does not send. */
export function twilioVoiceRequest(input: { accountSid: string; authToken: string; from: string; to: string; say: string }): VendorRequest {
  const twiml = `<Response><Say language="en-AU">${xmlEscape(input.say)}</Say></Response>`;
  return {
    url: `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(input.accountSid)}/Calls.json`,
    method: "POST",
    headers: {
      authorization: basic(input.accountSid, input.authToken),
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ To: input.to, From: input.from, Twiml: twiml }).toString(),
  };
}

async function postVendor(req: VendorRequest): Promise<DeliveryReceipt> {
  try {
    const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body, signal: AbortSignal.timeout(10_000) });
    const text = await res.text();
    if (!res.ok) return { status: "failed", providerRef: null, detail: `vendor ${res.status}` };
    let providerRef: string | null = null;
    try {
      const json = JSON.parse(text) as { messages?: { message_id?: string }[]; sid?: string };
      providerRef = json.messages?.[0]?.message_id ?? json.sid ?? null;
    } catch {
      providerRef = null;
    }
    return { status: "sent", providerRef, detail: "vendor accepted" };
  } catch (err) {
    return { status: "failed", providerRef: null, detail: err instanceof Error ? err.message : "vendor failed" };
  }
}

type SmsConfig = { from: string; mode: "fixture" | "live" };
type SmsSecrets = { apiKey: string; apiSecret: string };

export class SmsNotifier implements Notifier {
  constructor(private readonly config: SmsConfig, private readonly secrets: SmsSecrets) {}

  async send(n: Notification) {
    const result = await this.deliver(n);
    if (result.status === "failed") throw new Error(result.detail);
  }

  async deliver(n: Notification): Promise<DeliveryReceipt> {
    const to = n.to ?? "";
    if (!isAuNumber(this.config.from) || !isAuNumber(to)) return { status: "failed", providerRef: null, detail: "SMS needs an Australian +61 number" };
    const body = `${n.title}. ${n.summary}`.slice(0, 600);
    if (this.config.mode === "fixture") return { status: "sent", providerRef: "fixture-sms", detail: "fixture accepted" };
    return postVendor(messageMediaSmsRequest({ from: this.config.from, to, body, apiKey: this.secrets.apiKey, apiSecret: this.secrets.apiSecret }));
  }
}

type VoiceConfig = { from: string; mode: "fixture" | "live" };
type VoiceSecrets = { accountSid: string; authToken: string };

export class VoiceNotifier implements Notifier {
  constructor(private readonly config: VoiceConfig, private readonly secrets: VoiceSecrets) {}

  async send(n: Notification) {
    const result = await this.deliver(n);
    if (result.status === "failed") throw new Error(result.detail);
  }

  async deliver(n: Notification): Promise<DeliveryReceipt> {
    const to = n.to ?? "";
    if (!isAuNumber(this.config.from) || !isAuNumber(to)) return { status: "failed", providerRef: null, detail: "Voice needs an Australian +61 number" };
    const say = `${n.title}. ${n.summary}`.slice(0, 800);
    if (this.config.mode === "fixture") return { status: "sent", providerRef: "fixture-voice", detail: "fixture accepted" };
    return postVendor(twilioVoiceRequest({ accountSid: this.secrets.accountSid, authToken: this.secrets.authToken, from: this.config.from, to, say }));
  }
}

export function formatRfc5322(input: { from: string; to: string; subject: string; body: string }): string {
  const clean = (value: string) => value.replace(/[\r\n]/g, "");
  const body = input.body.replace(/\r?\n/g, "\r\n").split("\r\n").map((line) => (line.startsWith(".") ? `.${line}` : line)).join("\r\n");
  return [
    `From: ${clean(input.from)}`,
    `To: ${clean(input.to)}`,
    `Subject: ${clean(input.subject)}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    body,
  ].join("\r\n");
}

function readReplies(socket: net.Socket) {
  let buf = "";
  const pending: ((value: string) => void)[] = [];
  const complete = () => /^\d{3} /.test(buf.split("\r\n").filter((line) => line.length).at(-1) ?? "");
  const pump = () => {
    if (!pending.length || !complete()) return;
    const out = buf;
    buf = "";
    pending.shift()!(out);
  };
  socket.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    pump();
  });
  return () => new Promise<string>((resolve, reject) => {
    const fail = (err: Error) => reject(err);
    socket.once("error", fail);
    if (complete()) {
      const out = buf;
      buf = "";
      socket.off("error", fail);
      resolve(out);
      return;
    }
    pending.push((value) => {
      socket.off("error", fail);
      resolve(value);
    });
    socket.once("timeout", () => fail(new Error("smtp timeout")));
  });
}

async function expectCode(read: () => Promise<string>, code: string) {
  const reply = await read();
  const last = reply.split("\r\n").filter((line) => line.length).at(-1) ?? "";
  if (!last.startsWith(code)) throw new Error(`smtp expected ${code}`);
}

/** Speak SMTP to a relay. Tests point this at a local server. */
export async function sendSmtp(opts: {
  host: string;
  port: number;
  username: string;
  password: string;
  from: string;
  to: string;
  subject: string;
  body: string;
}): Promise<string> {
  const socket = net.connect({ host: opts.host, port: opts.port });
  socket.setTimeout(5_000);
  const read = readReplies(socket);
  try {
    await expectCode(read, "220");
    socket.write("EHLO blaksoc.local\r\n");
    await expectCode(read, "250");
    if (opts.username) {
      socket.write(`AUTH PLAIN ${Buffer.from(`\0${opts.username}\0${opts.password}`).toString("base64")}\r\n`);
      await expectCode(read, "235");
    }
    socket.write(`MAIL FROM:<${opts.from}>\r\n`);
    await expectCode(read, "250");
    socket.write(`RCPT TO:<${opts.to}>\r\n`);
    await expectCode(read, "250");
    socket.write("DATA\r\n");
    await expectCode(read, "354");
    socket.write(`${formatRfc5322(opts)}\r\n.\r\n`);
    await expectCode(read, "250");
    socket.write("QUIT\r\n");
    await expectCode(read, "221");
    return "smtp-accepted";
  } finally {
    socket.end();
    socket.destroy();
  }
}

type EmailConfig = { host: string; port: number; from: string; mode: "fixture" | "live" };
type EmailSecrets = { username: string; password: string };

export class EmailNotifier implements Notifier {
  constructor(private readonly config: EmailConfig, private readonly secrets: EmailSecrets) {}

  async send(n: Notification) {
    const result = await this.deliver(n);
    if (result.status === "failed") throw new Error(result.detail);
  }

  async deliver(n: Notification): Promise<DeliveryReceipt> {
    const to = n.to ?? "";
    if (!to.includes("@")) return { status: "failed", providerRef: null, detail: "email needs a destination address" };
    if (this.config.mode === "fixture") return { status: "sent", providerRef: "fixture-email", detail: "fixture accepted" };
    try {
      const providerRef = await sendSmtp({
        host: this.config.host,
        port: this.config.port,
        username: this.secrets.username,
        password: this.secrets.password,
        from: this.config.from,
        to,
        subject: n.title,
        body: n.summary,
      });
      return { status: "sent", providerRef, detail: "smtp accepted" };
    } catch (err) {
      return { status: "failed", providerRef: null, detail: err instanceof Error ? err.message : "smtp failed" };
    }
  }
}
