/** Technique ids named in an advisory, from explicit ATT&CK ids and a small phrase list. */
const PHRASES: [RegExp, string][] = [
  [/anydesk/i, "T1219"],
  [/screenconnect|connectwise control/i, "T1219"],
  [/teamviewer|splashtop|rustdesk|atera\b/i, "T1219"],
  [/shadow copy|vssadmin|inhibit system recovery/i, "T1490"],
  [/mimikatz|lsass|credential dump|procdump/i, "T1003.001"],
  [/lockbit|akira|rhysida|ransomware/i, "T1486"],
  [/fortigate|fortios|ivanti|citrix/i, "T1190"],
  [/encoded powershell|powershell -enc/i, "T1059.001"],
];

const TECHNIQUE = /\bT\d{4}(?:\.\d{3})?\b/gi;

export function extractAdvisoryTechniques(text: string): string[] {
  const explicit = [...text.matchAll(TECHNIQUE)].map((m) => m[0].toUpperCase());
  const hinted = PHRASES.filter(([rx]) => rx.test(text)).map(([, id]) => id);
  return [...new Set([...explicit, ...hinted])];
}

/** A named technique is covered when an enabled rule lists it or a parent/child of it. */
export function splitTechniqueCoverage(named: string[], coveredIds: readonly string[]) {
  const coveredSet = new Set(coveredIds.map((id) => id.toUpperCase()));
  const isCovered = (id: string) => {
    for (const have of coveredSet) {
      if (have === id || have.startsWith(`${id}.`) || id.startsWith(`${have}.`)) return true;
    }
    return false;
  };
  const ids = [...new Set(named.map((id) => id.toUpperCase()))];
  return { covered: ids.filter(isCovered), uncovered: ids.filter((id) => !isCovered(id)) };
}
