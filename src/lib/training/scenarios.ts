import { z } from "zod";
import type { DemoEventSpec } from "@/lib/providers/demo";
import { TRAINEE_ACTIONS, TRAINING_SKILLS, type TrainingSkill, type TraineeAction } from "./score";

const eventSchema = z.object({
  ruleId: z.string().min(1),
  level: z.number().int().min(0).max(15),
  title: z.string().min(3),
  groups: z.array(z.string().min(1)).min(1),
  mitre: z.array(z.string()),
  data: z.record(z.string(), z.unknown()),
  log: z.string().min(3),
});

export const scenarioSchema = z.object({
  id: z.string().regex(/^[a-z0-9-]{3,40}$/),
  title: z.string().min(3).max(80),
  summary: z.string().min(10).max(280),
  tags: z.array(z.string().min(1)).min(1),
  skills: z.array(z.enum(TRAINING_SKILLS)).min(1),
  hints: z.array(z.string().min(3)).min(1),
  expected: z.array(z.enum(TRAINEE_ACTIONS)).min(1),
  events: z.array(eventSchema).min(1),
});

export type TrainingScenario = {
  id: string;
  title: string;
  summary: string;
  tags: string[];
  skills: TrainingSkill[];
  hints: string[];
  expected: TraineeAction[];
  events: DemoEventSpec[];
};

const RAW: TrainingScenario[] = [
  {
    id: "bec-payment",
    title: "Payment redirect",
    summary: "A mailbox rule forwards invoices and a lookalike domain asks accounts to change the bank details.",
    tags: ["bec"],
    skills: ["alert:triage", "incident:write"],
    hints: ["Read the mailbox rule before anyone pays the invoice.", "The reply domain is not the vendor's usual domain."],
    expected: ["triage", "escalate", "note"],
    events: [{
      ruleId: "100501", level: 12, title: "Mailbox rule forwards invoices to an external address",
      groups: ["bec", "email"], mitre: ["T1114.003"], data: { dstuser: "accounts" },
      log: "Inbox rule forwards messages containing invoice to payee@vendor-payments.example",
    }],
  },
  {
    id: "ransomware-lock",
    title: "Mass file rename",
    summary: "A workstation renames thousands of files to a ransomware extension in under two minutes.",
    tags: ["ransomware"],
    skills: ["alert:triage", "response:request"],
    hints: ["The rename count is the containment signal.", "Ask for isolation before hunting the rest of the site."],
    expected: ["triage", "contain-request", "escalate"],
    events: [{
      ruleId: "100210", level: 14, title: "Mass file rename with ransomware extension",
      groups: ["ransomware", "syscheck"], mitre: ["T1486"], data: { dstuser: "j.nguyen" },
      log: "4812 files renamed to .lockbit in 90 seconds by lck.exe",
    }],
  },
  {
    id: "password-spray",
    title: "Password spray",
    summary: "One address fails logon against many users, then one account succeeds.",
    tags: ["identity"],
    skills: ["alert:triage", "asset:read"],
    hints: ["The success is the account that matters.", "Check whether that account is privileged."],
    expected: ["triage", "asset-check", "escalate"],
    events: [{
      ruleId: "60122", level: 10, title: "Password spray followed by one successful logon",
      groups: ["authentication_failed"], mitre: ["T1110.003"], data: { srcip: "203.0.113.40", dstuser: "svc-backup" },
      log: "40 users failed logon from 203.0.113.40 and svc-backup then succeeded",
    }],
  },
  {
    id: "encoded-powershell",
    title: "Encoded PowerShell",
    summary: "An admin session launches hidden encoded PowerShell that calls an external host.",
    tags: ["malware"],
    skills: ["alert:triage", "intel:read"],
    hints: ["The encoded command is the payload, not the logon.", "Check the destination host before closing it."],
    expected: ["triage", "intel-check", "escalate"],
    events: [{
      ruleId: "92057", level: 12, title: "Encoded PowerShell command executed",
      groups: ["powershell"], mitre: ["T1059.001"], data: { dstuser: "j.nguyen.admin" },
      log: "powershell -nop -w hidden -enc contacted update-check.example",
    }],
  },
  {
    id: "malware-hash",
    title: "Known malware hash",
    summary: "A new file in a public folder matches a known malware hash.",
    tags: ["malware"],
    skills: ["intel:read", "response:request"],
    hints: ["The hash match is already the verdict.", "Contain the host that wrote the file."],
    expected: ["intel-check", "contain-request", "note"],
    events: [{
      ruleId: "87105", level: 13, title: "Known malware hash written to disk",
      groups: ["malware"], mitre: ["T1105"], data: { dstuser: "j.nguyen" },
      log: "File added: C:\\Users\\Public\\svchost32.exe matches a known malware hash",
    }],
  },
  {
    id: "ssh-brute",
    title: "SSH brute force",
    summary: "Root password guesses hit a public SSH service from one address.",
    tags: ["network"],
    skills: ["alert:triage", "playbook:read"],
    hints: ["Root guesses on SSH are a containment candidate.", "Look up the playbook before you invent a new step."],
    expected: ["triage", "escalate", "note"],
    events: [{
      ruleId: "5712", level: 10, title: "SSHD brute force against root",
      groups: ["sshd"], mitre: ["T1110.001"], data: { srcip: "203.0.113.41", srcuser: "root" },
      log: "sshd failed password for root from 203.0.113.41",
    }],
  },
  {
    id: "web-scan",
    title: "Web login scan",
    summary: "One source requests a login page hundreds of times and gets nothing but errors.",
    tags: ["network"],
    skills: ["alert:triage"],
    hints: ["Error volume without a successful login is reconnaissance.", "Note the source and move on if nothing authenticated."],
    expected: ["triage", "note", "close"],
    events: [{
      ruleId: "31151", level: 6, title: "Repeated web login errors from one source",
      groups: ["web"], mitre: ["T1595"], data: { srcip: "203.0.113.42" },
      log: "GET /wp-login.php returned 404 from 203.0.113.42 two hundred times",
    }],
  },
  {
    id: "exploited-cve",
    title: "Known exploited CVE",
    summary: "The edge device is running a version with a known exploited vulnerability.",
    tags: ["vulnerability"],
    skills: ["asset:read", "intel:read"],
    hints: ["Match the package to the asset, not just the CVE name.", "Confirm the CVE is on the exploited list before escalating."],
    expected: ["asset-check", "intel-check", "escalate"],
    events: [{
      ruleId: "23505", level: 11, title: "Vulnerable package with a known exploited CVE",
      groups: ["vulnerability-detector"], mitre: ["T1190"], data: { vulnerability: { cve: "CVE-2024-3400" } },
      log: "CVE-2024-3400 affects the edge firewall GlobalProtect service",
    }],
  },
  {
    id: "oauth-consent",
    title: "Unexpected OAuth consent",
    summary: "A user grants a new mail-read application that the tenant has not used before.",
    tags: ["identity"],
    skills: ["alert:triage", "incident:write"],
    hints: ["The application name is the thing to write down.", "Mail-read consent is an incident, not a close."],
    expected: ["triage", "note", "escalate"],
    events: [{
      ruleId: "100610", level: 11, title: "New application consented to read mail",
      groups: ["oauth"], mitre: ["T1528"], data: { dstuser: "accounts" },
      log: "User accounts consented Mail.Read to app Invoice Helper",
    }],
  },
  {
    id: "impossible-travel",
    title: "Impossible travel",
    summary: "The same account signs in from two countries within twenty minutes.",
    tags: ["identity"],
    skills: ["alert:triage", "asset:read"],
    hints: ["Compare the two source addresses before you call it travel.", "Check the device that accepted the second sign-in."],
    expected: ["triage", "asset-check", "escalate"],
    events: [{
      ruleId: "100620", level: 10, title: "Account signed in from two countries within minutes",
      groups: ["authentication_success"], mitre: ["T1078"], data: { dstuser: "r.smith", srcip: "203.0.113.43" },
      log: "r.smith signed in from Sydney and then from an address in another country 12 minutes later",
    }],
  },
  {
    id: "public-share",
    title: "Public file share",
    summary: "A payroll folder is shared to anyone with the link.",
    tags: ["data"],
    skills: ["alert:triage", "incident:write"],
    hints: ["Anyone-with-the-link is the exposure.", "Write the folder name into the incident."],
    expected: ["triage", "note", "escalate"],
    events: [{
      ruleId: "100630", level: 9, title: "Payroll folder shared to anyone with the link",
      groups: ["cloud"], mitre: ["T1530"], data: { dstuser: "payroll" },
      log: "Folder Payroll 2026 changed to anyone with the link",
    }],
  },
];

export const SCENARIOS: TrainingScenario[] = z.array(scenarioSchema).min(10).parse(RAW);

export function scenarioById(id: string): TrainingScenario | null {
  return SCENARIOS.find((scenario) => scenario.id === id) ?? null;
}

export function listScenarios(): { id: string; title: string; tags: string[]; skills: TrainingSkill[] }[] {
  return SCENARIOS.map(({ id, title, tags, skills }) => ({ id, title, tags, skills }));
}
