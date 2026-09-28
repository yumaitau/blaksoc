/** ATT&CK Enterprise subset used until the full MITRE STIX bundle is imported (pnpm db:attack). */
export const ATTACK: [string, string, string[]][] = [
  ["T1595", "Active Scanning", ["reconnaissance"]],
  ["T1566", "Phishing", ["initial-access"]],
  ["T1566.001", "Spearphishing Attachment", ["initial-access"]],
  ["T1566.002", "Spearphishing Link", ["initial-access"]],
  ["T1190", "Exploit Public-Facing Application", ["initial-access"]],
  ["T1133", "External Remote Services", ["initial-access", "persistence"]],
  ["T1078", "Valid Accounts", ["initial-access", "persistence", "privilege-escalation", "defense-evasion"]],
  ["T1078.004", "Cloud Accounts", ["initial-access", "persistence", "privilege-escalation", "defense-evasion"]],
  ["T1059", "Command and Scripting Interpreter", ["execution"]],
  ["T1059.001", "PowerShell", ["execution"]],
  ["T1059.003", "Windows Command Shell", ["execution"]],
  ["T1059.004", "Unix Shell", ["execution"]],
  ["T1204", "User Execution", ["execution"]],
  ["T1204.002", "Malicious File", ["execution"]],
  ["T1047", "Windows Management Instrumentation", ["execution"]],
  ["T1053", "Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"]],
  ["T1053.005", "Scheduled Task", ["execution", "persistence", "privilege-escalation"]],
  ["T1547", "Boot or Logon Autostart Execution", ["persistence", "privilege-escalation"]],
  ["T1547.001", "Registry Run Keys / Startup Folder", ["persistence", "privilege-escalation"]],
  ["T1136", "Create Account", ["persistence"]],
  ["T1098", "Account Manipulation", ["persistence", "privilege-escalation"]],
  ["T1505.003", "Web Shell", ["persistence"]],
  ["T1068", "Exploitation for Privilege Escalation", ["privilege-escalation"]],
  ["T1548", "Abuse Elevation Control Mechanism", ["privilege-escalation", "defense-evasion"]],
  ["T1027", "Obfuscated Files or Information", ["defense-evasion"]],
  ["T1070", "Indicator Removal", ["defense-evasion"]],
  ["T1070.001", "Clear Windows Event Logs", ["defense-evasion"]],
  ["T1562", "Impair Defenses", ["defense-evasion"]],
  ["T1562.001", "Disable or Modify Tools", ["defense-evasion"]],
  ["T1218", "System Binary Proxy Execution", ["defense-evasion"]],
  ["T1218.011", "Rundll32", ["defense-evasion"]],
  ["T1036", "Masquerading", ["defense-evasion"]],
  ["T1110", "Brute Force", ["credential-access"]],
  ["T1110.001", "Password Guessing", ["credential-access"]],
  ["T1110.003", "Password Spraying", ["credential-access"]],
  ["T1003", "OS Credential Dumping", ["credential-access"]],
  ["T1003.001", "LSASS Memory", ["credential-access"]],
  ["T1555", "Credentials from Password Stores", ["credential-access"]],
  ["T1621", "Multi-Factor Authentication Request Generation", ["credential-access"]],
  ["T1087", "Account Discovery", ["discovery"]],
  ["T1082", "System Information Discovery", ["discovery"]],
  ["T1018", "Remote System Discovery", ["discovery"]],
  ["T1046", "Network Service Discovery", ["discovery"]],
  ["T1021", "Remote Services", ["lateral-movement"]],
  ["T1021.001", "Remote Desktop Protocol", ["lateral-movement"]],
  ["T1021.002", "SMB/Windows Admin Shares", ["lateral-movement"]],
  ["T1570", "Lateral Tool Transfer", ["lateral-movement"]],
  ["T1560", "Archive Collected Data", ["collection"]],
  ["T1114", "Email Collection", ["collection"]],
  ["T1071", "Application Layer Protocol", ["command-and-control"]],
  ["T1071.001", "Web Protocols", ["command-and-control"]],
  ["T1105", "Ingress Tool Transfer", ["command-and-control"]],
  ["T1572", "Protocol Tunneling", ["command-and-control"]],
  ["T1219", "Remote Access Software", ["command-and-control"]],
  ["T1041", "Exfiltration Over C2 Channel", ["exfiltration"]],
  ["T1567", "Exfiltration Over Web Service", ["exfiltration"]],
  ["T1567.002", "Exfiltration to Cloud Storage", ["exfiltration"]],
  ["T1486", "Data Encrypted for Impact", ["impact"]],
  ["T1490", "Inhibit System Recovery", ["impact"]],
  ["T1489", "Service Stop", ["impact"]],
  ["T1485", "Data Destruction", ["impact"]],
];

/** Feeds wired into OpenCTI (see deploy/opencti). License column is shown to admins before enabling. */
export const FEEDS = [
  { key: "mitre-attack", name: "MITRE ATT&CK", category: "framework", license: "MITRE ATT&CK Terms of Use (royalty-free)", connector: { image: "opencti/connector-mitre", createdBy: "The MITRE Corporation" } },
  { key: "cisa-kev", name: "CISA Known Exploited Vulnerabilities", category: "vulnerability", license: "US Government public domain", connector: { image: "opencti/connector-cisa-known-exploited-vulnerabilities", createdBy: "CISA" } },
  { key: "nvd-cve", name: "NVD CVE", category: "vulnerability", license: "NIST NVD public", connector: { image: "opencti/connector-cve", createdBy: "The MITRE Corporation" } },
  { key: "first-epss", name: "FIRST EPSS", category: "vulnerability", license: "FIRST EPSS — free, attribution requested", connector: { image: "opencti/connector-first-epss", createdBy: "FIRST" } },
  { key: "urlhaus", name: "URLhaus (abuse.ch)", category: "indicators", license: "abuse.ch — CC0", connector: { image: "opencti/connector-urlhaus", createdBy: "URLhaus (abuse.ch)" } },
  { key: "malwarebazaar", name: "MalwareBazaar (abuse.ch)", category: "indicators", license: "abuse.ch — CC0", connector: { image: "opencti/connector-malwarebazaar-recent-additions", createdBy: "MalwareBazaar (abuse.ch)" } },
  { key: "threatfox", name: "ThreatFox (abuse.ch)", category: "indicators", license: "abuse.ch — CC0", connector: { image: "opencti/connector-threatfox", createdBy: "ThreatFox (abuse.ch)" } },
  { key: "alienvault-otx", name: "AlienVault OTX", category: "indicators", license: "OTX terms — free account, non-commercial redistribution limits apply", connector: { image: "opencti/connector-alienvault", createdBy: "AlienVault OTX" } },
  { key: "circl-misp", name: "CIRCL OSINT MISP feed", category: "indicators", license: "CIRCL OSINT feed — TLP:CLEAR", connector: { image: "opencti/connector-misp-feed", createdBy: "CIRCL MISP feed" } },
  { key: "acsc-advisories", name: "ASD's ACSC alerts & advisories", category: "advisory", license: "© Commonwealth of Australia — CC BY 4.0 (check per item)", connector: { url: "https://www.cyber.gov.au/rss/alerts" }, notes: "Verify the current cyber.gov.au RSS endpoint before enabling in production." },
  { key: "cisa-advisories", name: "CISA cybersecurity advisories", category: "advisory", license: "US Government public domain", connector: { url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" } },
  { key: "recorded-future", name: "Recorded Future (commercial)", category: "indicators", license: "Commercial — per-customer licence required", commercial: true, enabled: false, connector: { image: "opencti/connector-recorded-future", createdBy: "Recorded Future" } },
] as const;

/** Seed CVE context; the worker overwrites with live CISA KEV / FIRST EPSS data on first run. */
export const CVES: { cve: string; summary: string; cvss: number; epss: number; pct: number; kev: boolean; ransomware?: boolean; due?: string }[] = [
  { cve: "CVE-2024-3400", summary: "Palo Alto PAN-OS GlobalProtect command injection", cvss: 10, epss: 0.957, pct: 0.999, kev: true, due: "2024-04-19" },
  { cve: "CVE-2023-4966", summary: "Citrix NetScaler ADC/Gateway information disclosure (Citrix Bleed)", cvss: 9.4, epss: 0.943, pct: 0.999, kev: true, ransomware: true, due: "2023-11-08" },
  { cve: "CVE-2024-21762", summary: "Fortinet FortiOS out-of-bound write in SSL VPN", cvss: 9.8, epss: 0.91, pct: 0.998, kev: true, due: "2024-02-16" },
  { cve: "CVE-2023-23397", summary: "Microsoft Outlook elevation of privilege", cvss: 9.8, epss: 0.92, pct: 0.998, kev: true, due: "2023-04-04" },
  { cve: "CVE-2021-44228", summary: "Apache Log4j2 remote code execution (Log4Shell)", cvss: 10, epss: 0.944, pct: 0.999, kev: true, ransomware: true, due: "2021-12-24" },
  { cve: "CVE-2024-6387", summary: "OpenSSH regreSSHion signal handler race", cvss: 8.1, epss: 0.38, pct: 0.97, kev: false },
  { cve: "CVE-2023-44487", summary: "HTTP/2 Rapid Reset", cvss: 7.5, epss: 0.81, pct: 0.99, kev: true, due: "2023-10-31" },
  { cve: "CVE-2024-38063", summary: "Windows TCP/IP IPv6 remote code execution", cvss: 9.8, epss: 0.05, pct: 0.92, kev: false },
  { cve: "CVE-2023-38545", summary: "curl SOCKS5 heap buffer overflow", cvss: 9.8, epss: 0.02, pct: 0.85, kev: false },
  { cve: "CVE-2022-0778", summary: "OpenSSL infinite loop in BN_mod_sqrt()", cvss: 7.5, epss: 0.01, pct: 0.7, kev: false },
];

export const SIGMA_RULES = [
  `title: Encoded PowerShell Command Line
id: 5e4c1f2a-7c1d-4f8b-9a2e-1b3c4d5e6f70
status: stable
description: Detects PowerShell launched with an encoded command, common in loaders and hands-on-keyboard activity.
author: Yuma IT blakSOC
logsource:
  product: windows
  category: process_creation
detection:
  selection_img:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_enc:
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - ' -e JAB'
  condition: all of selection_*
falsepositives:
  - Some management agents (SCCM, Intune scripts) use encoded commands
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1027
`,
  `title: LSASS Memory Access by Uncommon Process
id: 0f2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c80
status: experimental
description: Process opening LSASS with read access, indicative of credential dumping.
author: Yuma IT blakSOC
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1fffff'
  filter_legit:
    SourceImage|endswith:
      - '\\MsMpEng.exe'
      - '\\wmiprvse.exe'
  condition: selection and not filter_legit
falsepositives:
  - EDR and AV products
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
`,
  `title: Shadow Copy Deletion
id: 1a2b3c4d-6e7f-4a8b-9c0d-1e2f3a4b5c90
status: stable
description: Deletion of volume shadow copies, a common ransomware precursor.
author: Yuma IT blakSOC
logsource:
  product: windows
  category: process_creation
detection:
  selection_vss:
    Image|endswith: '\\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  selection_wmic:
    Image|endswith: '\\wmic.exe'
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  condition: 1 of selection_*
falsepositives:
  - Backup software maintenance (rare)
level: critical
tags:
  - attack.impact
  - attack.t1490
`,
  `title: SSH Brute Force From External Address
id: 2b3c4d5e-7f8a-4b9c-8d0e-2f3a4b5c6d01
status: stable
description: Repeated SSH authentication failures from a single source.
author: Yuma IT blakSOC
logsource:
  product: linux
  service: sshd
detection:
  keywords:
    - 'Failed password for'
    - 'authentication failure'
  condition: keywords
falsepositives:
  - Misconfigured automation with stale credentials
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001
`,
];
