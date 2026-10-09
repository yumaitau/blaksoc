export type DisplayLink = { id: string; name: string; tenantIds: string[]; createdBy: string; createdAt: string; expiresAt: string; revokedAt: string | null };

/** Fresh server rows take precedence; successful local changes remain visible during revalidation. */
export function displayLinkRows(server: readonly DisplayLink[], created: readonly DisplayLink[], revoked: Readonly<Record<string, string>>): DisplayLink[] {
  const rows = new Map(created.map((row) => [row.id, row]));
  for (const row of server) rows.set(row.id, row);
  return [...rows.values()]
    .map((row) => revoked[row.id] && !row.revokedAt ? { ...row, revokedAt: revoked[row.id]! } : row)
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}
