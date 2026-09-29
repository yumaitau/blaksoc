/**
 * Requirement text follows the ACSC Essential Eight maturity model (November 2023),
 * Appendices A to C. Application control on workstations also includes the November 2023
 * change: an application control solution, not NTFS permissions alone.
 * A requirement's minLevel is the first maturity level that lists it. Higher levels
 * still require it. Maturity Level Two and Three logging lines that are word-for-word
 * the same across strategies share one answerId.
 */

export const STRATEGIES = [
  { id: "patch_applications", label: "Patch applications", lead: "How fast you update programs and internet services." },
  { id: "patch_os", label: "Patch operating systems", lead: "How fast you update operating systems on computers and network devices." },
  { id: "mfa", label: "Multi-factor authentication", lead: "Whether sign-in needs more than a password." },
  { id: "restrict_admin", label: "Restrict administrative privileges", lead: "Who has administrator accounts, and how those accounts stay apart from everyday use." },
  { id: "application_control", label: "Application control", lead: "Whether only approved programs can run. A folder permission list is not application control." },
  { id: "office_macros", label: "Restrict Microsoft Office macros", lead: "Whether Office macros stay off unless someone has a real need." },
  { id: "user_app_hardening", label: "User application hardening", lead: "Whether browsers and Office are locked so staff cannot loosen them." },
  { id: "regular_backups", label: "Regular backups", lead: "Whether you can restore data, programs and settings. A Veeam connector can report last success, failed jobs, restore tests, and an offline or immutable copy. Other backup controls stay on your answer." },
] as const;

export type StrategyId = (typeof STRATEGIES)[number]["id"];

export const DISCLAIMER = "This is a self-assessment. It is not an ACSC-endorsed audit.";

export const MODEL_NOTE =
  "Levels follow the ACSC Essential Eight maturity model (November 2023). A level counts only when every requirement for that level is met. Maturity Level Zero means Maturity Level One is not met.";

export const CADENCE_DAYS = [90, 180, 365] as const;
export type CadenceDays = (typeof CADENCE_DAYS)[number];

export type Requirement = {
  id: string;
  strategy: StrategyId;
  minLevel: 1 | 2 | 3;
  answerId: string;
  text: string;
};

const req = (strategy: StrategyId, minLevel: 1 | 2 | 3, id: string, text: string, answerId = id): Requirement => ({
  id, strategy, minLevel, answerId, text,
});

const LOG_HOSTS: StrategyId[] = ["mfa", "restrict_admin", "application_control", "user_app_hardening"];

const SHARED_LOGS: { slug: string; minLevel: 2 | 3; text: string }[] = [
  { slug: "log-protected", minLevel: 2, text: "Event logs are protected from unauthorised modification and deletion." },
  { slug: "log-inet", minLevel: 2, text: "Event logs from internet-facing servers are analysed in a timely manner to detect cyber security events." },
  { slug: "log-events", minLevel: 2, text: "Cyber security events are analysed in a timely manner to identify cyber security incidents." },
  { slug: "log-ciso", minLevel: 2, text: "Cyber security incidents are reported to the chief information security officer, or one of their delegates, as soon as possible after they occur or are discovered." },
  { slug: "log-asd", minLevel: 2, text: "Cyber security incidents are reported to ASD as soon as possible after they occur or are discovered." },
  { slug: "log-irp", minLevel: 2, text: "Following the identification of a cyber security incident, the cyber security incident response plan is enacted." },
  { slug: "log-internal", minLevel: 3, text: "Event logs from non-internet-facing servers are analysed in a timely manner to detect cyber security events." },
  { slug: "log-workstations", minLevel: 3, text: "Event logs from workstations are analysed in a timely manner to detect cyber security events." },
];

function logsFor(strategy: StrategyId): Requirement[] {
  if (!LOG_HOSTS.includes(strategy)) return [];
  return SHARED_LOGS.map((row) => req(strategy, row.minLevel, `${strategy}-${row.slug}`, row.text, row.slug));
}

const SPECIFIC: Requirement[] = [
  req("patch_applications", 1, "pa-discover", "An automated method of asset discovery is used at least fortnightly to support the detection of assets for subsequent vulnerability scanning activities."),
  req("patch_applications", 1, "pa-scanner-db", "A vulnerability scanner with an up-to-date vulnerability database is used for vulnerability scanning activities."),
  req("patch_applications", 1, "pa-scan-online-daily", "A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in online services."),
  req("patch_applications", 1, "pa-scan-office-weekly", "A vulnerability scanner is used at least weekly to identify missing patches or updates for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products."),
  req("patch_applications", 1, "pa-online-48h", "Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist."),
  req("patch_applications", 1, "pa-online-2w", "Patches, updates or other vendor mitigations for vulnerabilities in online services are applied within two weeks of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist."),
  req("patch_applications", 1, "pa-office-2w", "Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within two weeks of release."),
  req("patch_applications", 1, "pa-remove-online", "Online services that are no longer supported by vendors are removed."),
  req("patch_applications", 1, "pa-remove-office", "Office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed."),
  req("patch_applications", 2, "pa-scan-other-fortnight", "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, and security products."),
  req("patch_applications", 2, "pa-other-1mo", "Patches, updates or other vendor mitigations for vulnerabilities in applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within one month of release."),
  req("patch_applications", 3, "pa-office-48h", "Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist."),
  req("patch_applications", 3, "pa-office-noncritical-2w", "Patches, updates or other vendor mitigations for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products are applied within two weeks of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist."),
  req("patch_applications", 3, "pa-remove-other", "Applications other than office productivity suites, web browsers and their extensions, email clients, PDF software, Adobe Flash Player, and security products that are no longer supported by vendors are removed."),

  req("patch_os", 1, "po-discover", "An automated method of asset discovery is used at least fortnightly to support the detection of assets for subsequent vulnerability scanning activities."),
  req("patch_os", 1, "po-scanner-db", "A vulnerability scanner with an up-to-date vulnerability database is used for vulnerability scanning activities."),
  req("patch_os", 1, "po-scan-inet-daily", "A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices."),
  req("patch_os", 1, "po-scan-ws-fortnight", "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices."),
  req("patch_os", 1, "po-inet-48h", "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist."),
  req("patch_os", 1, "po-inet-2w", "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing servers and internet-facing network devices are applied within two weeks of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist."),
  req("patch_os", 1, "po-ws-1mo", "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within one month of release."),
  req("patch_os", 1, "po-remove-unsupported", "Operating systems that are no longer supported by vendors are replaced."),
  req("patch_os", 3, "po-scan-drivers", "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in drivers."),
  req("patch_os", 3, "po-scan-firmware", "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in firmware."),
  req("patch_os", 3, "po-ws-48h", "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist."),
  req("patch_os", 3, "po-ws-noncritical-1mo", "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, non-internet-facing servers and non-internet-facing network devices are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist."),
  req("patch_os", 3, "po-drivers-48h", "Patches, updates or other vendor mitigations for vulnerabilities in drivers are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist."),
  req("patch_os", 3, "po-drivers-1mo", "Patches, updates or other vendor mitigations for vulnerabilities in drivers are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist."),
  req("patch_os", 3, "po-firmware-48h", "Patches, updates or other vendor mitigations for vulnerabilities in firmware are applied within 48 hours of release when vulnerabilities are assessed as critical by vendors or when working exploits exist."),
  req("patch_os", 3, "po-firmware-1mo", "Patches, updates or other vendor mitigations for vulnerabilities in firmware are applied within one month of release when vulnerabilities are assessed as non-critical by vendors and no working exploits exist."),
  req("patch_os", 3, "po-latest", "The latest release, or the previous release, of operating systems are used."),

  req("mfa", 1, "mfa-own-sensitive", "Multi-factor authentication is used to authenticate users to their organisation's online services that process, store or communicate their organisation's sensitive data."),
  req("mfa", 1, "mfa-third-sensitive", "Multi-factor authentication is used to authenticate users to third-party online services that process, store or communicate their organisation's sensitive data."),
  req("mfa", 1, "mfa-third-nonsensitive", "Multi-factor authentication (where available) is used to authenticate users to third-party online services that process, store or communicate their organisation's non-sensitive data."),
  req("mfa", 1, "mfa-own-customer", "Multi-factor authentication is used to authenticate users to their organisation's online customer services that process, store or communicate their organisation's sensitive customer data."),
  req("mfa", 1, "mfa-third-customer", "Multi-factor authentication is used to authenticate users to third-party online customer services that process, store or communicate their organisation's sensitive customer data."),
  req("mfa", 1, "mfa-customers", "Multi-factor authentication is used to authenticate customers to online customer services that process, store or communicate sensitive customer data."),
  req("mfa", 1, "mfa-factors", "Multi-factor authentication uses either: something users have and something users know, or something users have that is unlocked by something users know or are."),
  req("mfa", 2, "mfa-privileged-systems", "Multi-factor authentication is used to authenticate privileged users of systems."),
  req("mfa", 2, "mfa-unprivileged-systems", "Multi-factor authentication is used to authenticate unprivileged users of systems."),
  req("mfa", 2, "mfa-phish-online", "Multi-factor authentication used for authenticating users of online services is phishing-resistant."),
  req("mfa", 2, "mfa-phish-customers-option", "Multi-factor authentication used for authenticating customers of online customer services provides a phishing-resistant option."),
  req("mfa", 2, "mfa-phish-systems", "Multi-factor authentication used for authenticating users of systems is phishing-resistant."),
  req("mfa", 2, "mfa-events-logged", "Successful and unsuccessful multi-factor authentication events are centrally logged."),
  req("mfa", 3, "mfa-data-repos", "Multi-factor authentication is used to authenticate users of data repositories."),
  req("mfa", 3, "mfa-phish-customers", "Multi-factor authentication used for authenticating customers of online customer services is phishing-resistant."),
  req("mfa", 3, "mfa-phish-repos", "Multi-factor authentication used for authenticating users of data repositories is phishing-resistant."),

  req("restrict_admin", 1, "ra-validate", "Requests for privileged access to systems, applications and data repositories are validated when first requested."),
  req("restrict_admin", 1, "ra-dedicated", "Privileged users are assigned a dedicated privileged user account to be used solely for duties requiring privileged access."),
  req("restrict_admin", 1, "ra-no-internet", "Privileged user accounts (excluding those explicitly authorised to access online services) are prevented from accessing the internet, email and web services."),
  req("restrict_admin", 1, "ra-limited-online", "Privileged user accounts explicitly authorised to access online services are strictly limited to only what is required for users and services to undertake their duties."),
  req("restrict_admin", 1, "ra-separate-env", "Privileged users use separate privileged and unprivileged operating environments."),
  req("restrict_admin", 1, "ra-unpriv-no-priv-env", "Unprivileged user accounts cannot logon to privileged operating environments."),
  req("restrict_admin", 1, "ra-priv-no-unpriv-env", "Privileged user accounts (excluding local administrator accounts) cannot logon to unprivileged operating environments."),
  req("restrict_admin", 2, "ra-revalidate-12", "Privileged access to systems, applications and data repositories is disabled after 12 months unless revalidated."),
  req("restrict_admin", 2, "ra-inactive-45", "Privileged access to systems and applications is disabled after 45 days of inactivity."),
  req("restrict_admin", 2, "ra-not-virtualised", "Privileged operating environments are not virtualised within unprivileged operating environments."),
  req("restrict_admin", 2, "ra-jump", "Administrative activities are conducted through jump servers."),
  req("restrict_admin", 2, "ra-breakglass", "Credentials for break glass accounts, local administrator accounts and service accounts are long, unique, unpredictable and managed."),
  req("restrict_admin", 2, "ra-access-logged", "Privileged access events are centrally logged."),
  req("restrict_admin", 2, "ra-group-logged", "Privileged user account and security group management events are centrally logged."),
  req("restrict_admin", 3, "ra-least", "Privileged access to systems, applications and data repositories is limited to only what is required for users and services to undertake their duties."),
  req("restrict_admin", 3, "ra-saw", "Secure Admin Workstations are used in the performance of administrative activities."),
  req("restrict_admin", 3, "ra-jit", "Just-in-time administration is used for administering systems and applications."),
  req("restrict_admin", 3, "ra-memory-integrity", "Memory integrity functionality is enabled."),
  req("restrict_admin", 3, "ra-lsa", "Local Security Authority protection functionality is enabled."),
  req("restrict_admin", 3, "ra-cred-guard", "Credential Guard functionality is enabled."),
  req("restrict_admin", 3, "ra-remote-cred-guard", "Remote Credential Guard functionality is enabled."),

  req("application_control", 1, "ac-workstations", "Application control is implemented on workstations. The control is an application control solution built into the operating system or an equivalent third-party product. NTFS permissions alone do not meet this requirement."),
  req("application_control", 1, "ac-profiles", "Application control is applied to user profiles and temporary folders used by operating systems, web browsers and email clients."),
  req("application_control", 1, "ac-types", "Application control restricts the execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets to an organisation-approved set."),
  req("application_control", 2, "ac-inet-servers", "Application control is implemented on internet-facing servers, using an application control solution rather than file permissions alone."),
  req("application_control", 2, "ac-all-locations", "Application control is applied to all locations other than user profiles and temporary folders used by operating systems, web browsers and email clients."),
  req("application_control", 2, "ac-blocklist", "Microsoft's recommended application blocklist is implemented."),
  req("application_control", 2, "ac-ruleset-annual", "Application control rulesets are validated on an annual or more frequent basis."),
  req("application_control", 2, "ac-events-logged", "Allowed and blocked application control events are centrally logged."),
  req("application_control", 3, "ac-internal-servers", "Application control is implemented on non-internet-facing servers, using an application control solution rather than file permissions alone."),
  req("application_control", 3, "ac-drivers", "Application control restricts the execution of drivers to an organisation-approved set."),
  req("application_control", 3, "ac-vulnerable-drivers", "Microsoft's vulnerable driver blocklist is implemented."),

  req("office_macros", 1, "om-disabled", "Microsoft Office macros are disabled for users that do not have a demonstrated business requirement."),
  req("office_macros", 1, "om-internet", "Microsoft Office macros in files originating from the internet are blocked."),
  req("office_macros", 1, "om-antivirus", "Microsoft Office macro antivirus scanning is enabled."),
  req("office_macros", 1, "om-users", "Microsoft Office macro security settings cannot be changed by users."),
  req("office_macros", 2, "om-win32", "Microsoft Office macros are blocked from making Win32 API calls."),
  req("office_macros", 3, "om-sandbox", "Only Microsoft Office macros running from within a sandboxed environment, a Trusted Location or that are digitally signed by a trusted publisher are allowed to execute."),
  req("office_macros", 3, "om-checked", "Microsoft Office macros are checked to ensure they are free of malicious code before being digitally signed or placed within Trusted Locations."),
  req("office_macros", 3, "om-trusted-writers", "Only privileged users responsible for checking that Microsoft Office macros are free of malicious code can write to and modify content within Trusted Locations."),
  req("office_macros", 3, "om-untrusted-publisher", "Microsoft Office macros digitally signed by an untrusted publisher cannot be enabled via the Message Bar or Backstage View."),
  req("office_macros", 3, "om-v3", "Microsoft Office macros digitally signed by signatures other than V3 signatures cannot be enabled via the Message Bar or Backstage View."),
  req("office_macros", 3, "om-publishers-annual", "Microsoft Office's list of trusted publishers is validated on an annual or more frequent basis."),

  req("user_app_hardening", 1, "uh-ie", "Internet Explorer 11 is disabled or removed."),
  req("user_app_hardening", 1, "uh-java", "Web browsers do not process Java from the internet."),
  req("user_app_hardening", 1, "uh-ads", "Web browsers do not process web advertisements from the internet."),
  req("user_app_hardening", 1, "uh-browser-settings", "Web browser security settings cannot be changed by users."),
  req("user_app_hardening", 2, "uh-browser-guidance", "Web browsers are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur."),
  req("user_app_hardening", 2, "uh-office-child", "Microsoft Office is blocked from creating child processes."),
  req("user_app_hardening", 2, "uh-office-exe", "Microsoft Office is blocked from creating executable content."),
  req("user_app_hardening", 2, "uh-office-inject", "Microsoft Office is blocked from injecting code into other processes."),
  req("user_app_hardening", 2, "uh-office-ole", "Microsoft Office is configured to prevent activation of Object Linking and Embedding packages."),
  req("user_app_hardening", 2, "uh-office-guidance", "Office productivity suites are hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur."),
  req("user_app_hardening", 2, "uh-office-settings", "Office productivity suite security settings cannot be changed by users."),
  req("user_app_hardening", 2, "uh-pdf-child", "PDF software is blocked from creating child processes."),
  req("user_app_hardening", 2, "uh-pdf-guidance", "PDF software is hardened using ASD and vendor hardening guidance, with the most restrictive guidance taking precedence when conflicts occur."),
  req("user_app_hardening", 2, "uh-pdf-settings", "PDF software security settings cannot be changed by users."),
  req("user_app_hardening", 2, "uh-ps-logging", "PowerShell module logging, script block logging and transcription events are centrally logged."),
  req("user_app_hardening", 2, "uh-cmdline", "Command line process creation events are centrally logged."),
  req("user_app_hardening", 3, "uh-dotnet", ".NET Framework 3.5 (includes .NET 2.0 and 3.0) is disabled or removed."),
  req("user_app_hardening", 3, "uh-ps2", "Windows PowerShell 2.0 is disabled or removed."),
  req("user_app_hardening", 3, "uh-clm", "PowerShell is configured to use Constrained Language Mode."),

  req("regular_backups", 1, "bk-criticality", "Backups of data, applications and settings are performed and retained in accordance with business criticality and business continuity requirements."),
  req("regular_backups", 1, "bk-sync", "Backups of data, applications and settings are synchronised to enable restoration to a common point in time."),
  req("regular_backups", 1, "bk-resilient", "Backups of data, applications and settings are retained in a secure and resilient manner."),
  req("regular_backups", 1, "bk-restore-tested", "Restoration of data, applications and settings from backups to a common point in time is tested as part of disaster recovery exercises."),
  req("regular_backups", 1, "bk-unpriv-others", "Unprivileged user accounts cannot access backups belonging to other user accounts."),
  req("regular_backups", 1, "bk-unpriv-modify", "Unprivileged user accounts are prevented from modifying and deleting backups."),
  req("regular_backups", 2, "bk-priv-others", "Privileged user accounts (excluding backup administrator accounts) cannot access backups belonging to other user accounts."),
  req("regular_backups", 2, "bk-priv-modify", "Privileged user accounts (excluding backup administrator accounts) are prevented from modifying and deleting backups."),
  req("regular_backups", 3, "bk-unpriv-own", "Unprivileged user accounts cannot access their own backups."),
  req("regular_backups", 3, "bk-priv-own", "Privileged user accounts (excluding backup administrator accounts) cannot access their own backups."),
  req("regular_backups", 3, "bk-admin-retention", "Backup administrator accounts are prevented from modifying and deleting backups during their retention period."),
];

function sorted(list: Requirement[]): Requirement[] {
  return [...list].sort((a, b) => a.minLevel - b.minLevel || a.id.localeCompare(b.id));
}

export const REQUIREMENTS: Requirement[] = STRATEGIES.flatMap((strategy) =>
  sorted([...SPECIFIC.filter((row) => row.strategy === strategy.id), ...logsFor(strategy.id)]),
);

const ANSWER_IDS = [...new Set(REQUIREMENTS.map((row) => row.answerId))];

export function answerIds(): string[] {
  return ANSWER_IDS;
}

export type QuestionGroup = {
  id: string;
  title: string;
  note: string;
  questions: { answerId: string; minLevel: 1 | 2 | 3; text: string }[];
};

export function questionGroups(): QuestionGroup[] {
  const counts = new Map<string, number>();
  for (const row of REQUIREMENTS) counts.set(row.answerId, (counts.get(row.answerId) ?? 0) + 1);
  const shared = new Set([...counts.entries()].filter(([, n]) => n > 1).map(([id]) => id));
  const dedupe = (rows: Requirement[]) => {
    const seen = new Set<string>();
    const questions: QuestionGroup["questions"] = [];
    for (const row of rows) {
      if (seen.has(row.answerId)) continue;
      seen.add(row.answerId);
      questions.push({ answerId: row.answerId, minLevel: row.minLevel, text: row.text });
    }
    return questions;
  };
  return [
    ...STRATEGIES.map((strategy) => ({
      id: strategy.id,
      title: strategy.label,
      note: strategy.lead,
      questions: dedupe(REQUIREMENTS.filter((row) => row.strategy === strategy.id && !shared.has(row.answerId))),
    })),
    {
      id: "shared-logs",
      title: "Logging and incident response",
      note: "The maturity model lists these checks under multi-factor authentication, restrict administrative privileges, application control, and user application hardening. One answer counts for each of those strategies.",
      questions: dedupe(REQUIREMENTS.filter((row) => shared.has(row.answerId))),
    },
  ];
}
