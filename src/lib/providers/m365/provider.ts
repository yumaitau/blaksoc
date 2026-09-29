import type { AlertQuery, NormalisedAlert, NormalisedAsset, ProviderHealth, ResponseActionRequest, ResponseActionResult, SecurityEventProvider } from "@/lib/providers/types";
import { graphList, graphRequest, liveGraphTransport, type GraphTransport } from "./graph";
import { demoGraphTransport } from "./fixtures";
import { coverageGaps, type CoverageGap } from "./licence";
import { advanceCheckpoint, deriveCorrelations, emptyCheckpoint, normaliseDevice, normaliseDirectoryAudit, normaliseExchange, normaliseSignIn, normaliseUser, parseCheckpoint, type M365Checkpoint } from "./normalise";
import type { MfaPoint, SignInPoint } from "@/lib/detections/bec";

export const ENTRA_REMOTE_PERMISSIONS = [
  "Microsoft Graph application: AuditLog.Read.All",
  "Microsoft Graph application: Directory.Read.All",
  "Microsoft Graph application: User.Read.All",
  "Microsoft Graph application: User.EnableDisableAccount.All",
  "Microsoft Graph application: User.RevokeSessions.All",
  "Microsoft Graph application: UserAuthenticationMethod.ReadWrite.All",
  "Microsoft Graph application: IdentityRiskyUser.Read.All",
  "Microsoft Graph application: IdentityRiskEvent.Read.All",
  "Microsoft Graph application: Organization.Read.All",
  "Microsoft Graph application: DelegatedPermissionGrant.ReadWrite.All",
  "Microsoft Graph application: MailboxSettings.ReadWrite",
  "Microsoft Graph application: DeviceManagementManagedDevices.Read.All",
  "Office 365 Management APIs application: ActivityFeed.Read",
];

export const M365_RESPONSE_ACTIONS = ["disable_identity", "revoke_sessions", "require_mfa", "remove_inbox_rule", "revoke_oauth_grant"] as const;

export type M365Config = { azureTenantId: string; mode: "live" | "fixture"; subscribedSkus: string[] };
export type M365Secrets = { clientId?: string; clientSecret?: string };

/** 404 on a delete means the rule, grant, or method is already gone. Disable is a no-op when the account is already disabled. */
export function actionResult(action: string, status: number): ResponseActionResult {
  if (status === 200 || status === 202 || status === 204) return { ok: true, message: `${action} applied`, providerRef: `graph:${action}` };
  if (status === 404 && (action === "remove_inbox_rule" || action === "revoke_oauth_grant" || action === "require_mfa")) {
    return { ok: true, message: `${action} already absent`, providerRef: `graph:${action}` };
  }
  return { ok: false, message: `${action} failed (${status})` };
}

export class M365Provider implements SecurityEventProvider {
  readonly kind = "entra";
  private cache = new Map<string, NormalisedAlert>();
  private apiDenied: string[] = [];

  constructor(
    private readonly config: M365Config,
    private readonly secrets: M365Secrets,
    private readonly transport: GraphTransport,
    private readonly sleep?: (ms: number) => Promise<void>,
  ) {}

  private signal(id: string): CoverageGap {
    return this.gaps().find((g) => g.id === id)!;
  }

  gaps(): CoverageGap[] {
    return coverageGaps(this.config.subscribedSkus).map((g) =>
      this.apiDenied.includes(g.id) ? { ...g, available: false, reason: "Graph returned 403 for this signal" } : g,
    );
  }

  supportedActions(): ResponseActionRequest["action"][] {
    return [...M365_RESPONSE_ACTIONS];
  }

  async getAlerts(q: AlertQuery): Promise<{ alerts: NormalisedAlert[]; cursor: string | null }> {
    this.assertLiveCreds();
    const cp = parseCheckpoint(q.afterCursor, q.since);
    const alerts: NormalisedAlert[] = [];
    const ids: string[] = [];
    const signIns: SignInPoint[] = [...cp.signIns];
    const mfa: MfaPoint[] = [];
    const mailboxUsers = new Set<string>();

    if (this.signal("signins").available) {
      const page = await graphList(this.transport, "/auditLogs/signIns", undefined, { sleep: this.sleep });
      if (page.denied) this.apiDenied.push("signins");
      for (const raw of page.records) {
        const row = normaliseSignIn(raw, cp);
        if (row.point) signIns.push(row.point);
        if (row.mfa) mfa.push(row.mfa);
        if (row.alert) alerts.push(row.alert);
        if (typeof raw.id === "string") ids.push(raw.id);
      }
    }

    if (this.signal("directory_audit").available || this.signal("oauth_consent").available) {
      const page = await graphList(this.transport, "/auditLogs/directoryAudits", undefined, { sleep: this.sleep });
      if (page.denied) this.apiDenied.push("directory_audit");
      for (const raw of page.records) {
        const alert = normaliseDirectoryAudit(raw, cp);
        if (alert) alerts.push(alert);
        if (typeof raw.id === "string") ids.push(raw.id);
      }
    }

    if (this.signal("risk_detections").available) {
      const page = await graphList(this.transport, "/identityProtection/riskDetections", undefined, { sleep: this.sleep });
      if (page.denied) this.apiDenied.push("risk_detections");
      for (const raw of page.records) if (typeof raw.id === "string") ids.push(raw.id);
    }

    if (this.signal("unified_audit").available) {
      const url = `https://manage.office.com/api/v1.0/${encodeURIComponent(this.config.azureTenantId)}/activity/feed/subscriptions/content?contentType=Audit.Exchange`;
      const page = await graphList(this.transport, url, undefined, { sleep: this.sleep });
      if (page.denied) this.apiDenied.push("unified_audit");
      const records: Record<string, unknown>[] = [];
      for (const row of page.records) {
        const uri = typeof row.contentUri === "string" ? row.contentUri : "";
        const contentId = typeof row.contentId === "string" ? row.contentId : "";
        if (uri) {
          if (contentId && cp.seen.includes(contentId)) continue;
          const blob = await graphList(this.transport, uri, undefined, { sleep: this.sleep });
          records.push(...blob.records);
          if (contentId) ids.push(contentId);
        } else {
          records.push(row);
          const id = String(row.Id ?? row.id ?? "");
          if (id) ids.push(id);
        }
      }
      for (const raw of records) {
        const row = normaliseExchange(raw, cp);
        if (row.mailboxUser) mailboxUsers.add(row.mailboxUser.toLowerCase());
        if (row.alert) alerts.push(row.alert);
      }
    }

    for (const alert of deriveCorrelations(signIns, mailboxUsers, mfa, cp)) alerts.push(alert);
    for (const alert of alerts) {
      this.cache.set(alert.externalId, alert);
      ids.push(alert.externalId);
    }
    const next: M365Checkpoint = advanceCheckpoint(cp, ids, signIns.filter((s) => !cp.signIns.some((h) => h.id === s.id)));
    return { alerts, cursor: JSON.stringify(next) };
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
    this.assertLiveCreds();
    const users = await graphList(this.transport, "/users", undefined, { sleep: this.sleep });
    const assets = users.records.map(normaliseUser).filter((a): a is NormalisedAsset => !!a);
    if (this.signal("intune_devices").available) {
      const devices = await graphList(this.transport, "/deviceManagement/managedDevices", undefined, { sleep: this.sleep });
      if (devices.denied) this.apiDenied.push("intune_devices");
      else assets.push(...devices.records.map(normaliseDevice).filter((a): a is NormalisedAsset => !!a));
    }
    return assets;
  }

  async getAsset(externalId: string): Promise<NormalisedAsset | null> {
    return (await this.getAssets()).find((a) => a.externalId === externalId) ?? null;
  }

  async executeResponseAction(req: ResponseActionRequest): Promise<ResponseActionResult> {
    if (!this.supportedActions().includes(req.action)) return { ok: false, message: `${this.kind} does not support ${req.action}` };
    const user = encodeURIComponent(req.assetExternalId);
    if (this.config.mode === "fixture") {
      return { ok: true, message: `fixture ${req.action} on ${req.assetExternalId}`, providerRef: `fixture:${req.action}:${req.assetExternalId}` };
    }
    this.assertLiveCreds();
    if (req.action === "disable_identity") {
      const current = await graphRequest(this.transport, "GET", `/users/${user}`, { query: { $select: "accountEnabled" }, sleep: this.sleep });
      const enabled = current.body && typeof current.body === "object" ? (current.body as { accountEnabled?: boolean }).accountEnabled : undefined;
      if (enabled === false) return { ok: true, message: "disable_identity already applied", providerRef: `graph:disable_identity:${req.assetExternalId}` };
      const res = await graphRequest(this.transport, "PATCH", `/users/${user}`, { body: { accountEnabled: false }, sleep: this.sleep });
      const out = actionResult(req.action, res.status);
      return { ...out, providerRef: `graph:disable_identity:${req.assetExternalId}` };
    }
    if (req.action === "revoke_sessions") {
      const res = await graphRequest(this.transport, "POST", `/users/${user}/revokeSignInSessions`, { sleep: this.sleep });
      return actionResult(req.action, res.status);
    }
    if (req.action === "require_mfa") {
      const methods = await graphList(this.transport, `/users/${user}/authentication/methods`, undefined, { sleep: this.sleep });
      if (!methods.records.length) return { ok: true, message: "require_mfa already absent", providerRef: `graph:require_mfa:${req.assetExternalId}` };
      for (const method of methods.records) {
        const id = String(method.id ?? "");
        if (!id) continue;
        const res = await graphRequest(this.transport, "DELETE", `/users/${user}/authentication/methods/${encodeURIComponent(id)}`, { sleep: this.sleep });
        const out = actionResult(req.action, res.status);
        if (!out.ok) return out;
      }
      return { ok: true, message: "require_mfa applied", providerRef: `graph:require_mfa:${req.assetExternalId}` };
    }
    if (req.action === "remove_inbox_rule") {
      const ruleId = String(req.params?.ruleId ?? "");
      if (!ruleId) return { ok: false, message: "remove_inbox_rule requires ruleId" };
      const res = await graphRequest(this.transport, "DELETE", `/users/${user}/mailFolders/inbox/messageRules/${encodeURIComponent(ruleId)}`, { sleep: this.sleep });
      return actionResult(req.action, res.status);
    }
    const grantId = String(req.params?.grantId ?? "");
    if (!grantId) return { ok: false, message: "revoke_oauth_grant requires grantId" };
    const res = await graphRequest(this.transport, "DELETE", `/oauth2PermissionGrants/${encodeURIComponent(grantId)}`, { sleep: this.sleep });
    return actionResult(req.action, res.status);
  }

  async health(): Promise<ProviderHealth> {
    const gaps = this.gaps();
    if (this.config.mode === "fixture") return { ok: true, latencyMs: 1, detail: { mode: "fixture", gaps } };
    const start = Date.now();
    try {
      this.assertLiveCreds();
      const res = await graphRequest(this.transport, "GET", "/organization", { query: { $select: "id,displayName" }, sleep: this.sleep });
      if (res.status >= 400) return { ok: false, latencyMs: Date.now() - start, detail: { gaps }, error: `Graph ${res.status}` };
      return { ok: true, latencyMs: Date.now() - start, detail: { mode: "live", gaps } };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - start, detail: { gaps }, error: (err as Error).message };
    }
  }

  private assertLiveCreds() {
    if (this.config.mode === "fixture") return;
    if (!this.secrets.clientId || !this.secrets.clientSecret) throw new Error("entra live mode needs clientId and clientSecret");
  }
}

export function createM365Provider(config: M365Config, secrets: M365Secrets, transport?: GraphTransport) {
  const chosen = transport ?? (config.mode === "fixture"
    ? demoGraphTransport()
    : liveGraphTransport({ azureTenantId: config.azureTenantId, clientId: secrets.clientId ?? "", clientSecret: secrets.clientSecret ?? "" }));
  return new M365Provider(config, secrets, chosen);
}

export { emptyCheckpoint };
