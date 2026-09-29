/** Hot window for firewall lines. Older lines move to the cold archive. */
export const SYSLOG_HOT_MS = 30 * 86_400_000;

export const AU_ARCHIVE_REGIONS = ["ap-southeast-2", "ap-southeast-4"] as const;
export type AuArchiveRegion = (typeof AU_ARCHIVE_REGIONS)[number];

export function assertAuRegion(region: string): asserts region is AuArchiveRegion {
  if (!(AU_ARCHIVE_REGIONS as readonly string[]).includes(region)) {
    throw new Error(`archive region must be in Australia, got ${region}`);
  }
}

export function archiveKey(tenantId: string, eventId: string): string {
  return `syslog/${tenantId}/${eventId}.log`;
}
