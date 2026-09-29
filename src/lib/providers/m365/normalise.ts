import { alertFromDetection, correlateImpossibleTravel, correlateMfaFatigue, paymentKeywords, type MfaPoint, type SignInPoint } from "@/lib/detections/bec";
import type { NormalisedAlert, NormalisedAsset } from "@/lib/providers/types";

const LEGACY_APPS = ["imap", "pop", "smtp", "mapi", "other clients", "exchange activesync", "authenticated smtp"];
const MAIL_SCOPES = ["mail.read", "mail.readwrite", "mail.send", "mailboxsettings.readwrite"];

export type M365Checkpoint = {
  since: string;
  seen: string[];
  signIns: SignInPoint[];
};

export function emptyCheckpoint(since: Date): M365Checkpoint {
  return { since: since.toISOString(), seen: [], signIns: [] };
}

export function parseCheckpoint(cursor: string | undefined, since: Date | undefined): M365Checkpoint {
  if (cursor) {
    try {
      const parsed = JSON.parse(cursor) as M365Checkpoint;
      if (parsed && typeof parsed.since === "string" && Array.isArray(parsed.seen)) {
        return { since: parsed.since, seen: parsed.seen, signIns: parsed.signIns ?? [] };
      }
    } catch {
      /* a foreign cursor (another provider) starts a fresh window */
    }
  }
  return emptyCheckpoint(since ?? new Date(Date.now() - 24 * 3600_000));
}

function str(v: unknown): string {
  return typeof v === "string" ? v : v == null ? "" : String(v);
}

function atOf(raw: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = raw[k];
    if (typeof v === "string" && v) return v;
  }
  return new Date(0).toISOString();
}

function fresh(id: string, at: string, cp: M365Checkpoint): boolean {
  if (!id || cp.seen.includes(id)) return false;
  return Date.parse(at) >= Date.parse(cp.since);
}

function param(raw: Record<string, unknown>, name: string): string {
  const list = raw.Parameters ?? raw.parameters;
  if (!Array.isArray(list)) return "";
  const hit = list.find((p) => p && typeof p === "object" && str((p as { Name?: string }).Name).toLowerCase() === name.toLowerCase()) as { Value?: unknown } | undefined;
  return str(hit?.Value);
}

export function normaliseSignIn(raw: Record<string, unknown>, cp: M365Checkpoint): { alert: NormalisedAlert | null; point: SignInPoint | null; mfa: MfaPoint | null } {
  const id = str(raw.id);
  const at = atOf(raw, "createdDateTime");
  const user = str(raw.userPrincipalName);
  const country = str((raw.location as { countryOrRegion?: string } | undefined)?.countryOrRegion);
  const ip = str(raw.ipAddress);
  const point = id && user ? { id, user, country, ip, at } : null;
  if (!fresh(id, at, cp)) return { alert: null, point: null, mfa: null };
  const app = str(raw.clientAppUsed).toLowerCase();
  const error = Number((raw.status as { errorCode?: number } | undefined)?.errorCode ?? 0);
  const requirement = str(raw.authenticationRequirement).toLowerCase();
  const mfa = requirement.includes("multifactor") ? { id, user, at, denied: error !== 0, success: error === 0 } : null;
  const legacy = LEGACY_APPS.some((a) => app.includes(a));
  if (!legacy) return { alert: null, point, mfa };
  return {
    point,
    mfa,
    alert: alertFromDetection({
      externalId: `signin:${id}`,
      title: `Legacy authentication sign-in (${str(raw.clientAppUsed) || "unknown"})`,
      description: `${user} signed in with a legacy protocol from ${country || "an unknown country"}.`,
      severity: "medium",
      occurredAt: new Date(at),
      userName: user || null,
      assetExternalId: str(raw.userId) || null,
      techniques: ["T1078"],
      raw: { ...raw, eventType: "legacy_auth", clientApp: str(raw.clientAppUsed), ruleId: undefined, grantId: undefined },
    }),
  };
}

export function normaliseDirectoryAudit(raw: Record<string, unknown>, cp: M365Checkpoint): NormalisedAlert | null {
  const id = str(raw.id);
  const at = atOf(raw, "activityDateTime");
  if (!fresh(id, at, cp)) return null;
  const name = str(raw.activityDisplayName).toLowerCase();
  const user = str((raw.initiatedBy as { user?: { userPrincipalName?: string } } | undefined)?.user?.userPrincipalName);
  const target = (Array.isArray(raw.targetResources) ? raw.targetResources[0] : null) as { id?: string; displayName?: string; modifiedProperties?: { displayName?: string; newValue?: string }[] } | null;
  const props = target?.modifiedProperties ?? [];
  const blob = JSON.stringify(props).toLowerCase();
  if (name.includes("consent to application")) {
    const scopes = props.find((p) => /scope|permission/i.test(str(p.displayName)))?.newValue ?? blob;
    const publisher = /verifiedpublisher|verified publisher/.test(blob) && !/unverified/.test(blob) ? "verified" : "unverified";
    const mail = MAIL_SCOPES.some((s) => scopes.toLowerCase().includes(s));
    if (!(publisher === "unverified" && mail)) return null;
    return alertFromDetection({
      externalId: `audit:${id}`,
      title: "Suspicious OAuth consent for mail",
      description: `${user || "A user"} consented an unverified app to mail scopes.`,
      severity: "high",
      occurredAt: new Date(at),
      userName: user || null,
      assetExternalId: str(target?.id) || null,
      techniques: ["T1528"],
      raw: { ...raw, eventType: "oauth_consent", publisher, scopes, grantId: str(target?.id), ruleId: undefined },
    });
  }
  if (name.includes("add member to role") || (name.includes("update user") && /mfa|authentication method|strongauthentication/.test(blob))) {
    return {
      externalId: `audit:${id}`,
      ruleId: "directory_audit",
      title: name.includes("role") ? "Admin role assigned" : "MFA method changed",
      description: str(raw.activityDisplayName),
      category: "identity",
      siemSeverity: 12,
      severity: "high",
      occurredAt: new Date(at),
      assetExternalId: str(target?.id) || null,
      hostname: null,
      userName: user || null,
      attackTechniques: ["T1098"],
      routingKeys: user ? [`upn:${user.toLowerCase()}`] : [],
      raw: { ...raw, eventType: "account_change" },
    };
  }
  return null;
}

export function normaliseExchange(raw: Record<string, unknown>, cp: M365Checkpoint): { alert: NormalisedAlert | null; mailboxUser: string | null } {
  const id = str(raw.Id ?? raw.id);
  const at = atOf(raw, "CreationTime", "creationTime");
  if (!fresh(id, at, cp)) return { alert: null, mailboxUser: null };
  const op = str(raw.Operation ?? raw.operation).toLowerCase();
  const user = str(raw.UserId ?? raw.userId);
  const userId = str(raw.UserKey ?? raw.userKey) || null;
  if (op.includes("inboxrule")) {
    const words = `${param(raw, "SubjectContainsWords")} ${param(raw, "BodyContainsWords")} ${param(raw, "Name")}`;
    const keywords = paymentKeywords(words);
    const deleteMessage = /true/i.test(param(raw, "DeleteMessage"));
    const move = param(raw, "MoveToFolder").length > 0;
    if (!keywords.length || (!deleteMessage && !move)) return { alert: null, mailboxUser: user || null };
    return {
      mailboxUser: user || null,
      alert: alertFromDetection({
        externalId: `o365:${id}`,
        title: "Inbox rule hiding payment messages",
        description: `${user} created a rule that ${deleteMessage ? "deletes" : "moves"} mail mentioning ${keywords.join(", ")}.`,
        severity: "high",
        occurredAt: new Date(at),
        userName: user || null,
        assetExternalId: userId,
        techniques: ["T1114.003"],
        raw: { ...raw, eventType: "inbox_rule", disposition: deleteMessage ? "delete" : "move", keywords: keywords.join(" "), ruleId: param(raw, "Identity") || id, grantId: undefined },
      }),
    };
  }
  if (op.includes("set-mailbox") || op === "set-mailbox") {
    const forward = param(raw, "ForwardingSmtpAddress") || param(raw, "ForwardingAddress");
    if (!forward) return { alert: null, mailboxUser: user || null };
    const domain = user.split("@")[1]?.toLowerCase() ?? "";
    const target = forward.replace(/^smtp:/i, "").toLowerCase();
    const external = domain && target.endsWith(`@${domain}`) ? "no" : "yes";
    if (external !== "yes") return { alert: null, mailboxUser: user || null };
    return {
      mailboxUser: user || null,
      alert: alertFromDetection({
        externalId: `o365:${id}`,
        title: "Mailbox forwarding to an external address",
        description: `${user} forwards mail to ${target}.`,
        severity: "high",
        occurredAt: new Date(at),
        userName: user || null,
        assetExternalId: userId,
        techniques: ["T1114.003"],
        raw: { ...raw, eventType: "mailbox_forward", external, forwardingAddress: target, ruleId: undefined, grantId: undefined },
      }),
    };
  }
  if (op === "send" || op === "sendas" || op === "sendonbehalf") {
    const count = Number(raw.RecipientCount ?? raw.recipientCount ?? 0);
    if (!(count >= 50)) return { alert: null, mailboxUser: user || null };
    return {
      mailboxUser: user || null,
      alert: alertFromDetection({
        externalId: `o365:${id}`,
        title: "Mass email send",
        description: `${user} sent a message to ${count} recipients.`,
        severity: "high",
        occurredAt: new Date(at),
        userName: user || null,
        assetExternalId: userId,
        techniques: ["T1566.002"],
        raw: { ...raw, eventType: "mass_mail", recipientCount: count },
      }),
    };
  }
  return { alert: null, mailboxUser: null };
}

export function deriveCorrelations(signIns: SignInPoint[], mailboxUsers: Set<string>, mfa: MfaPoint[], cp: M365Checkpoint): NormalisedAlert[] {
  const out: NormalisedAlert[] = [];
  for (const hit of correlateImpossibleTravel(signIns, mailboxUsers)) {
    if (cp.seen.includes(hit.id)) continue;
    out.push(alertFromDetection({
      externalId: hit.id,
      title: "Impossible travel followed by mailbox activity",
      description: `${hit.user} signed in from ${hit.from.country} and then ${hit.to.country} inside two hours, and the mailbox was used.`,
      severity: "high",
      occurredAt: new Date(hit.to.at),
      userName: hit.user,
      assetExternalId: null,
      techniques: ["T1078", "T1114.003"],
      raw: { eventType: "impossible_travel", mailboxActivity: "yes", countries: `${hit.from.country},${hit.to.country}`, ip: hit.to.ip, ruleId: undefined, grantId: undefined },
    }));
  }
  for (const hit of correlateMfaFatigue(mfa)) {
    if (cp.seen.includes(hit.id)) continue;
    out.push(alertFromDetection({
      externalId: hit.id,
      title: "MFA fatigue (denied prompts, then approval)",
      description: `${hit.user} denied MFA ${hit.denied} times and then approved a prompt.`,
      severity: "high",
      occurredAt: new Date(hit.at),
      userName: hit.user,
      assetExternalId: null,
      techniques: ["T1621"],
      raw: { eventType: "mfa_fatigue", outcome: "approved", deniedCount: hit.denied },
    }));
  }
  return out;
}

export function normaliseUser(raw: Record<string, unknown>): NormalisedAsset | null {
  const id = str(raw.id);
  const upn = str(raw.userPrincipalName);
  if (!id || !upn) return null;
  return {
    externalId: id,
    kind: "identity",
    name: str(raw.displayName) || upn,
    hostname: null,
    ips: [],
    os: null,
    macs: [],
    agentStatus: raw.accountEnabled === false ? "disabled" : "active",
    lastSeen: null,
    routingKeys: [`upn:${upn.toLowerCase()}`],
    raw,
  };
}

export function normaliseDevice(raw: Record<string, unknown>): NormalisedAsset | null {
  const id = str(raw.id);
  const name = str(raw.deviceName);
  if (!id || !name) return null;
  const mac = str(raw.wiFiMacAddress || raw.ethernetMacAddress);
  return {
    externalId: id,
    kind: "endpoint",
    name,
    hostname: name,
    ips: [],
    os: str(raw.operatingSystem) || null,
    macs: mac ? [mac] : [],
    agentStatus: str(raw.complianceState) || "unknown",
    lastSeen: raw.lastSyncDateTime ? new Date(str(raw.lastSyncDateTime)) : null,
    routingKeys: [`device:${name.toLowerCase()}`],
    raw,
  };
}

export function advanceCheckpoint(cp: M365Checkpoint, ids: string[], signIns: SignInPoint[]): M365Checkpoint {
  const times = signIns.map((s) => Date.parse(s.at)).filter((n) => Number.isFinite(n));
  const max = times.length ? Math.max(...times, Date.parse(cp.since)) : Date.parse(cp.since);
  const seen = [...cp.seen, ...ids].slice(-2000);
  const history = [...cp.signIns, ...signIns].slice(-200);
  return { since: new Date(max).toISOString(), seen, signIns: history };
}
