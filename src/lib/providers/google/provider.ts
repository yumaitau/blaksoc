import type { AlertQuery, NormalisedAlert, NormalisedAsset, ProviderHealth, ResponseActionRequest, ResponseActionResult, SecurityEventProvider } from "@/lib/providers/types";

export const GOOGLE_REMOTE_PERMISSIONS = [
  "Admin SDK domain-wide delegation: https://www.googleapis.com/auth/admin.reports.audit.readonly",
  "Admin SDK domain-wide delegation: https://www.googleapis.com/auth/admin.directory.user.readonly",
  "Admin SDK domain-wide delegation: https://www.googleapis.com/auth/admin.directory.user.security",
  "Admin SDK domain-wide delegation: https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
  "Admin SDK domain-wide delegation: https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
];

export const GOOGLE_RESPONSE_ACTIONS = ["suspend_user", "sign_out", "reset_signin_cookies", "revoke_oauth_token", "revoke_sessions", "reset_password"] as const;

export type GoogleConfig = { customerId: string; domain: string; mode: "fixture" | "live" };
export type GoogleSecrets = { clientEmail?: string; privateKey?: string };

/** Admin SDK Reports API URL. Live mode names this URL and does not call it from tests or demo. */
export function adminReportUrl(application: "login" | "admin" | "drive" | "token", customerId: string): string {
  return `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/${application}?customerId=${encodeURIComponent(customerId)}`;
}

export function directoryUrl(kind: "users" | "chromeos" | "mobile" | "suspend" | "signOut" | "tokens", customerId: string, userKey = ""): string {
  const base = "https://admin.googleapis.com/admin/directory/v1";
  if (kind === "users") return `${base}/users?customer=${encodeURIComponent(customerId)}`;
  if (kind === "chromeos") return `${base}/customer/${encodeURIComponent(customerId)}/devices/chromeos`;
  if (kind === "mobile") return `${base}/customer/${encodeURIComponent(customerId)}/devices/mobile`;
  const user = encodeURIComponent(userKey);
  if (kind === "suspend" || kind === "signOut") return `${base}/users/${user}${kind === "signOut" ? "/signOut" : ""}`;
  return `${base}/users/${user}/tokens/client`;
}

function alert(partial: Omit<NormalisedAlert, "routingKeys" | "attackTechniques" | "siemSeverity" | "ruleId"> & { ruleId: string }): NormalisedAlert {
  return { ...partial, ruleId: partial.ruleId, siemSeverity: null, attackTechniques: [], routingKeys: [] };
}

export function fixtureGoogleAlerts(domain: string, now = new Date()): NormalisedAlert[] {
  const user = `ada@${domain}`;
  const at = new Date(now.getTime() - 3_600_000);
  return [
    alert({ externalId: "gw:login:suspicious", ruleId: "google.login.suspicious", title: "Suspicious login", description: `${user} signed in from a new country.`, category: "login", severity: "high", occurredAt: at, assetExternalId: user, hostname: null, userName: user, raw: { application: "login", event: "login_challenge" } }),
    alert({ externalId: "gw:admin:2sv", ruleId: "google.admin.2sv_disabled", title: "2-step verification disabled", description: `2-step verification was turned off for ${user}.`, category: "admin", severity: "high", occurredAt: at, assetExternalId: user, hostname: null, userName: user, raw: { application: "admin", event: "2sv_disable" } }),
    alert({ externalId: "gw:admin:privilege", ruleId: "google.admin.privilege", title: "Admin privilege granted", description: `${user} was granted an admin role.`, category: "admin", severity: "critical", occurredAt: at, assetExternalId: user, hostname: null, userName: user, raw: { application: "admin", event: "GRANT_ADMIN_PRIVILEGE" } }),
    alert({ externalId: "gw:drive:share", ruleId: "google.drive.external_share", title: "Mass external share", description: `A Drive folder was shared outside ${domain}. Treat shared files as sensitive, including cultural material.`, category: "drive", severity: "high", occurredAt: at, assetExternalId: user, hostname: null, userName: user, raw: { application: "drive", event: "change_document_visibility", count: 40 } }),
    alert({ externalId: "gw:token:oauth", ruleId: "google.token.oauth", title: "Third-party OAuth grant", description: `${user} granted a third-party app access.`, category: "token", severity: "medium", occurredAt: at, assetExternalId: user, hostname: null, userName: user, raw: { application: "token", event: "authorize", clientId: "third-party" } }),
  ];
}

export function fixtureGoogleAssets(domain: string): NormalisedAsset[] {
  const user = `ada@${domain}`;
  const seen = new Date();
  return [
    { externalId: user, kind: "identity", name: user, hostname: null, ips: [], os: null, macs: [], agentStatus: null, lastSeen: seen, routingKeys: [], raw: { kind: "user" } },
    { externalId: "chromeos-1", kind: "endpoint", name: "Front desk Chromebook", hostname: "front-desk", ips: [], os: "ChromeOS", macs: [], agentStatus: "active", lastSeen: seen, routingKeys: [], raw: { kind: "chromeos" } },
    { externalId: "mobile-1", kind: "endpoint", name: "Field phone", hostname: "field-phone", ips: [], os: "Android", macs: [], agentStatus: "active", lastSeen: seen, routingKeys: [], raw: { kind: "mobile" } },
  ];
}

export class GoogleWorkspaceProvider implements SecurityEventProvider {
  readonly kind = "google-workspace";
  private cache = new Map<string, NormalisedAlert>();

  constructor(
    private readonly config: GoogleConfig,
    private readonly secrets: GoogleSecrets,
  ) {}

  supportedActions(): ResponseActionRequest["action"][] {
    return [...GOOGLE_RESPONSE_ACTIONS];
  }

  private assertFixture() {
    if (this.config.mode === "live") {
      const url = adminReportUrl("login", this.config.customerId);
      if (!this.secrets.clientEmail || !this.secrets.privateKey) throw new Error(`google workspace live mode needs a service account (${url})`);
      throw new Error(`google workspace live mode is refused in this process (${url})`);
    }
  }

  async getAlerts(_q: AlertQuery): Promise<{ alerts: NormalisedAlert[]; cursor: string | null }> {
    this.assertFixture();
    const alerts = fixtureGoogleAlerts(this.config.domain);
    for (const row of alerts) this.cache.set(row.externalId, row);
    return { alerts, cursor: null };
  }

  async getAlert(externalId: string): Promise<NormalisedAlert | null> {
    return this.cache.get(externalId) ?? null;
  }

  async searchEvents(q: AlertQuery): Promise<{ total: number; events: Record<string, unknown>[] }> {
    const { alerts } = await this.getAlerts(q);
    const events = alerts.map((a) => a.raw);
    const filtered = q.query ? events.filter((e) => JSON.stringify(e).toLowerCase().includes(q.query!.toLowerCase())) : events;
    return { total: filtered.length, events: filtered };
  }

  async getAssets(): Promise<NormalisedAsset[]> {
    this.assertFixture();
    return fixtureGoogleAssets(this.config.domain);
  }

  async getAsset(externalId: string): Promise<NormalisedAsset | null> {
    return (await this.getAssets()).find((a) => a.externalId === externalId) ?? null;
  }

  async executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult> {
    if (!this.supportedActions().includes(req.action)) return { ok: false, message: `${this.kind} does not support ${req.action}` };
    this.assertFixture();
    return { ok: true, message: `fixture ${req.action} on ${req.assetExternalId}`, providerRef: `fixture:${req.action}:${req.assetExternalId}` };
  }

  async health(): Promise<ProviderHealth> {
    return { ok: true, latencyMs: 1, detail: { mode: this.config.mode, customerId: this.config.customerId } };
  }
}

export function createGoogleProvider(config: GoogleConfig, secrets: GoogleSecrets): GoogleWorkspaceProvider {
  return new GoogleWorkspaceProvider(config, secrets);
}
