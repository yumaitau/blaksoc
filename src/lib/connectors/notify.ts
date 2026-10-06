import { createHmac } from "node:crypto";
import { egressFetch } from "@/lib/net/egress";

export type Notification = {
  event: string;
  tenant: { id: string; name: string };
  title: string;
  severity?: string;
  url: string;
  summary: string;
  /** Phone or email the escalation step selected. Webhooks ignore it. */
  to?: string;
};

export type DeliveryReceipt = {
  status: "sent" | "failed";
  providerRef: string | null;
  detail: string;
};

export interface Notifier {
  send(n: Notification): Promise<void>;
  deliver(n: Notification): Promise<DeliveryReceipt>;
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
    // Webhooks, Teams and Slack are SaaS endpoints: private and metadata addresses are refused.
    const res = await egressFetch(this.url, { method: "POST", headers, body: payload, signal: AbortSignal.timeout(10_000) }, "public");
    if (!res.ok) throw new Error(`webhook ${res.status}`);
  }

  async deliver(n: Notification): Promise<DeliveryReceipt> {
    try {
      await this.send(n);
      return { status: "sent", providerRef: null, detail: "webhook accepted" };
    } catch (err) {
      return { status: "failed", providerRef: null, detail: err instanceof Error ? err.message : "webhook failed" };
    }
  }
}
