import { evaluateRule, type CorrelationEvent } from "@/lib/correlation/engine";
import { IMPOSSIBLE_TRAVEL, MFA_FATIGUE } from "@/lib/correlation/rules";
import type { NormalisedAlert, Severity } from "@/lib/providers/types";

/**
 * BEC / email-threat pack.
 * Single-event detections are Sigma. Impossible travel and MFA fatigue are correlation engine rules
 * (src/lib/correlation/rules.ts) run over the provider's raw sign-ins; they emit an event the matching Sigma rule then classifies.
 * Payment-keyword inbox rules, external forwarding, suspicious OAuth, legacy auth, and mass send are Sigma-only.
 */

export type SigmaCase = { name: string; event: Record<string, unknown>; expect: boolean };

const PAYMENT_WORDS = ["invoice", "payment", "bank", "eft", "remittance"];

function rule(yaml: string, cases: SigmaCase[]) {
  return { yaml, cases };
}

export const BEC_DETECTIONS: { yaml: string; cases: SigmaCase[] }[] = [
  rule(
    `title: Impossible travel sign-in followed by mailbox activity
id: 11111111-1111-4111-8111-111111111111
status: stable
description: Native correlator correlateImpossibleTravel emits this event when two sign-ins from different countries fall inside two hours and the same account touches the mailbox.
author: Yuma IT blakSOC
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    eventType: impossible_travel
    mailboxActivity: "yes"
  condition: selection
falsepositives:
  - Staff who travel with a VPN exit in another country
level: high
tags:
  - attack.initial_access
  - attack.t1078
  - attack.collection
  - attack.t1114.003
`,
    [
      { name: "travel then mailbox", event: { eventType: "impossible_travel", mailboxActivity: "yes" }, expect: true },
      { name: "travel without mailbox", event: { eventType: "impossible_travel", mailboxActivity: "no" }, expect: false },
    ],
  ),
  rule(
    `title: Inbox rule hiding payment messages
id: 22222222-2222-4222-8222-222222222222
status: stable
description: New or changed inbox rule that deletes or moves mail whose subject mentions invoices, payments, bank details, EFT, or remittance.
author: Yuma IT blakSOC
logsource:
  product: m365
  service: exchange
detection:
  selection:
    eventType: inbox_rule
    disposition|contains:
      - delete
      - move
    keywords|contains:
      - invoice
      - payment
      - bank
      - eft
      - remittance
  condition: selection
falsepositives:
  - A finance clerk who files invoices into a folder they still read
level: high
tags:
  - attack.collection
  - attack.t1114.003
`,
    [
      { name: "delete invoice mail", event: { eventType: "inbox_rule", disposition: "delete", keywords: "invoice" }, expect: true },
      { name: "file newsletters", event: { eventType: "inbox_rule", disposition: "move", keywords: "newsletter" }, expect: false },
    ],
  ),
  rule(
    `title: External mailbox auto-forward
id: 33333333-3333-4333-8333-333333333333
status: stable
description: Mailbox forwarding turned on to an address outside the organisation.
author: Yuma IT blakSOC
logsource:
  product: m365
  service: exchange
detection:
  selection:
    eventType: mailbox_forward
    external: "yes"
  condition: selection
falsepositives:
  - A shared mailbox deliberately copied to an approved partner domain
level: high
tags:
  - attack.collection
  - attack.t1114.003
`,
    [
      { name: "forward outside", event: { eventType: "mailbox_forward", external: "yes" }, expect: true },
      { name: "forward inside", event: { eventType: "mailbox_forward", external: "no" }, expect: false },
    ],
  ),
  rule(
    `title: MFA fatigue then approval
id: 44444444-4444-4444-8444-444444444444
status: stable
description: Native correlator correlateMfaFatigue emits this event after at least three denied MFA prompts and then an approval inside 60 minutes.
author: Yuma IT blakSOC
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    eventType: mfa_fatigue
    outcome: approved
  condition: selection
falsepositives:
  - A user who denies a prompt they did not expect, then approves the real one once
level: high
tags:
  - attack.credential_access
  - attack.t1621
`,
    [
      { name: "denied then approved", event: { eventType: "mfa_fatigue", outcome: "approved" }, expect: true },
      { name: "still denied", event: { eventType: "mfa_fatigue", outcome: "denied" }, expect: false },
    ],
  ),
  rule(
    `title: Suspicious mail OAuth consent
id: 55555555-5555-4555-8555-555555555555
status: stable
description: Consent to an unverified application that asks for high-privilege mail scopes.
author: Yuma IT blakSOC
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    eventType: oauth_consent
    publisher: unverified
    scopes|contains:
      - Mail.Read
      - Mail.ReadWrite
      - Mail.Send
      - MailboxSettings.ReadWrite
  condition: selection
falsepositives:
  - A verified Microsoft app the organisation chose to trust
level: high
tags:
  - attack.credential_access
  - attack.t1528
`,
    [
      { name: "unverified mail app", event: { eventType: "oauth_consent", publisher: "unverified", scopes: "Mail.Read Mail.Send" }, expect: true },
      { name: "verified profile app", event: { eventType: "oauth_consent", publisher: "verified", scopes: "User.Read" }, expect: false },
    ],
  ),
  rule(
    `title: Legacy authentication sign-in
id: 66666666-6666-4666-8666-666666666666
status: stable
description: Sign-in with a legacy protocol that bypasses modern MFA (IMAP, POP, SMTP AUTH, MAPI, ActiveSync).
author: Yuma IT blakSOC
logsource:
  product: azure
  service: signinlogs
detection:
  selection:
    eventType: legacy_auth
  condition: selection
falsepositives:
  - A scanner or copier that still sends scan-to-email with SMTP AUTH
level: medium
tags:
  - attack.initial_access
  - attack.t1078
`,
    [
      { name: "imap sign-in", event: { eventType: "legacy_auth", clientApp: "IMAP" }, expect: true },
      { name: "browser sign-in", event: { eventType: "browser_auth", clientApp: "Browser" }, expect: false },
    ],
  ),
  rule(
    `title: Mass mail or internal phishing after compromise
id: 77777777-7777-4777-8777-777777777777
status: stable
description: One account sends mail to 50 or more recipients in a single operation.
author: Yuma IT blakSOC
logsource:
  product: m365
  service: exchange
detection:
  selection:
    eventType: mass_mail
  condition: selection
falsepositives:
  - A newsletter mailbox the organisation already uses for staff notices
level: high
tags:
  - attack.initial_access
  - attack.t1566.002
`,
    [
      { name: "eighty recipients", event: { eventType: "mass_mail", recipientCount: 80 }, expect: true },
      { name: "three recipients", event: { eventType: "single_mail", recipientCount: 3 }, expect: false },
    ],
  ),
];

export const SUSPECTED_BEC_PLAYBOOK = {
  name: "Suspected BEC",
  description: "Suspected business email compromise. Enrich the sign-in, open an incident, tell the customer, then wait for approval before revoking sessions, disabling the user, and removing malicious inbox rules.",
  enabled: false,
  trigger: { event: "alert.created" as const, conditions: [{ field: "alert.category", op: "eq" as const, value: "bec" }] },
  steps: [
    { id: "intel", action: "intel.enrich", name: "Enrich sign-in IPs via OpenCTI" },
    { id: "incident", action: "incident.create", name: "Create incident", params: { title: "Suspected BEC" } },
    { id: "notify", action: "notify", name: "Notify the customer contact", params: { title: "Suspected business email compromise", message: "We think someone is misusing a mailbox. Open the portal for what happened and what we need from you. We also text the after-hours contact when SMS is connected." } },
    { id: "gate", action: "approval.request", name: "Approval gate before containment", params: { summary: "Approve revoking sessions, disabling the user, and removing malicious inbox rules?" } },
    { id: "revoke", action: "revoke_sessions", name: "Revoke sessions" },
    { id: "disable", action: "disable_identity", name: "Disable user" },
    { id: "rules", action: "remove_inbox_rule", name: "Remove malicious inbox rules" },
    {
      id: "tasks",
      action: "task.create",
      name: "Customer task list",
      params: {
        titles: [
          "Call your bank and ask them to hold unusual payments",
          "Check recent changes to payment details with suppliers",
          "Notify ACSC via ReportCyber",
          "Consider a Notifiable Data Breach assessment",
        ],
      },
    },
  ],
};

export type SignInPoint = { id: string; user: string; country: string; ip: string; at: string };

/** Two countries inside two hours, and the account has mailbox activity. Runs the IMPOSSIBLE_TRAVEL engine rule. */
export function correlateImpossibleTravel(signIns: SignInPoint[], mailboxUsers: Set<string>, windowMs = 2 * 3600_000) {
  const rule = { ...IMPOSSIBLE_TRAVEL, clause: { ...IMPOSSIBLE_TRAVEL.clause, within: windowMs } };
  const byId = new Map(signIns.map((s) => [s.id, s]));
  const events: CorrelationEvent[] = [
    ...signIns.map((s) => ({ id: s.id, at: Date.parse(s.at), fields: { event_type: "signin", user: s.user, country: s.country, src_ip: s.ip, summary: `sign-in from ${s.country || "an unknown country"}${s.ip ? ` (${s.ip})` : ""}` } })),
    // Mailbox use carries no time here: the provider only knows which accounts touched a mailbox this poll.
    ...[...mailboxUsers].map((u) => ({ id: `mailbox:${u}`, at: 0, fields: { event_type: "mailbox_activity", user: u, summary: "mailbox activity" } })),
  ];
  return evaluateRule(rule, events).map((f) => {
    const from = byId.get(f.matches[0]!.events[0]!.id)!;
    const to = byId.get(f.anchorId)!;
    return { id: `travel:${from.id}:${to.id}`, user: to.user, from, to, matches: f.matches };
  });
}

export type MfaPoint = { id: string; user: string; at: string; denied: boolean; success: boolean };

/** At least three MFA denials, then a success, all inside 60 minutes. Runs the MFA_FATIGUE engine rule. */
export function correlateMfaFatigue(points: MfaPoint[], windowMs = 60 * 60_000) {
  const rule = { ...MFA_FATIGUE, clause: { ...MFA_FATIGUE.clause, within: windowMs } };
  const byId = new Map(points.map((p) => [p.id, p]));
  const events: CorrelationEvent[] = points.map((p) => ({
    id: p.id,
    at: Date.parse(p.at),
    fields: { event_type: p.denied ? "mfa_denied" : p.success ? "mfa_success" : "mfa_prompt", user: p.user, summary: p.denied ? "MFA prompt denied" : "MFA prompt approved" },
  }));
  return evaluateRule(rule, events).map((f) => {
    const ok = byId.get(f.anchorId)!;
    return { id: `mfa:${ok.id}`, user: ok.user, denied: f.matches[0]!.events.length, successId: ok.id, at: ok.at, matches: f.matches };
  });
}

export function paymentKeywords(text: string): string[] {
  const hay = text.toLowerCase();
  return PAYMENT_WORDS.filter((w) => hay.includes(w));
}

export function alertFromDetection(input: {
  externalId: string;
  title: string;
  description: string;
  severity: Severity;
  occurredAt: Date;
  userName: string | null;
  assetExternalId: string | null;
  techniques: string[];
  raw: Record<string, unknown>;
  hostname?: string | null;
}): NormalisedAlert {
  return {
    externalId: input.externalId,
    ruleId: String(input.raw.eventType ?? "bec"),
    title: input.title,
    description: input.description,
    category: "bec",
    siemSeverity: input.severity === "high" ? 12 : input.severity === "critical" ? 14 : 8,
    severity: input.severity,
    occurredAt: input.occurredAt,
    assetExternalId: input.assetExternalId,
    hostname: input.hostname ?? null,
    userName: input.userName,
    attackTechniques: input.techniques,
    routingKeys: input.userName ? [`upn:${input.userName.toLowerCase()}`] : [],
    raw: input.raw,
  };
}
