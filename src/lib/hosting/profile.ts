import { AU_ARCHIVE_REGIONS } from "@/lib/syslog/retain";

/** `AU` is the policy flag. Bucket regions are the archive list. */
export function allowedDataRegions(): readonly string[] {
  return ["AU", ...AU_ARCHIVE_REGIONS];
}

export function regionStoresOutsideAustralia(region: string): boolean {
  return !allowedDataRegions().includes(region);
}

export function hostingComponents(aiResidency: string, archiveRegion: string): { name: string; region: string }[] {
  return [
    { name: "ai-policy", region: aiResidency },
    { name: "syslog-archive", region: archiveRegion },
  ];
}

export function componentsOutsideAustralia(rows: { region: string }[]): string[] {
  return rows.filter((row) => regionStoresOutsideAustralia(row.region)).map((row) => row.region);
}

/** First `key: scalar` in a small Helm values file. */
export function helmScalar(yaml: string, key: string): string | null {
  for (const line of yaml.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith(`${key}:`)) continue;
    let value = trimmed.slice(key.length + 1).trim();
    const hash = value.indexOf(" #");
    if (hash >= 0) value = value.slice(0, hash).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    return value;
  }
  return null;
}

/** First scalar under a top-level block. Stops at the next sibling key. */
export function helmBlockScalar(yaml: string, block: string, key: string): string | null {
  const lines = yaml.split("\n");
  let inBlock = false;
  let indent = 0;
  for (const line of lines) {
    if (!inBlock) {
      const match = new RegExp(`^(\\s*)${block}:\\s*$`).exec(line);
      const captured = match?.[1];
      if (captured === undefined) continue;
      inBlock = true;
      indent = captured.length;
      continue;
    }
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const current = line.match(/^(\s*)/)?.[1]?.length ?? 0;
    if (current <= indent) return null;
    const trimmed = line.trim();
    if (!trimmed.startsWith(`${key}:`)) continue;
    return trimmed.slice(key.length + 1).trim();
  }
  return null;
}
