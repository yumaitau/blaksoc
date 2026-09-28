import { createHmac } from "node:crypto";

export type Notification = {
  event: string;
  tenant: { id: string; name: string };
  title: string;
  severity?: string;
  url: string;
  summary: string;
};

export interface Notifier {
  send(n: Notification): Promise<void>;
}

export class WebhookNotifier implements Notifier {
  constructor(private readonly url: string, private readonly secret: string | null, private readonly flavour: "generic" | "teams" | "slack" = "generic") {}

  async send(n: Notification) {
    const body =
      this.flavour === "slack"
        ? { text: `*${n.title}* (${n.tenant.name})\n${n.summary}\n<${n.url}|Open in blakSOC>` }
        : this.flavour === "teams"
          ? {
              type: "message",
              attachments: [{
                contentType: "application/vnd.microsoft.card.adaptive",
                content: {
                  type: "AdaptiveCard", version: "1.4",
                  body: [
                    { type: "TextBlock", weight: "Bolder", text: n.title, wrap: true },
                    { type: "TextBlock", text: `${n.tenant.name}${n.severity ? ` · ${n.severity}` : ""}`, isSubtle: true },
                    { type: "TextBlock", text: n.summary, wrap: true },
                  ],
                  actions: [{ type: "Action.OpenUrl", title: "Open in blakSOC", url: n.url }],
                },
              }],
            }
          : n;
    const payload = JSON.stringify(body);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.secret) {
      const ts = Math.floor(Date.now() / 1000).toString();
      headers["x-blaksoc-timestamp"] = ts;
      headers["x-blaksoc-signature"] = `sha256=${createHmac("sha256", this.secret).update(`${ts}.${payload}`).digest("hex")}`;
    }
    const res = await fetch(this.url, { method: "POST", headers, body: payload, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`webhook ${res.status}`);
  }
}
