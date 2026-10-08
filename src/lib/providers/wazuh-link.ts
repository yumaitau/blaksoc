const risonString = (s: string) => `'${s.replaceAll("!", "!!").replaceAll("'", "!'")}'`;

/** Open Discover on the indexer document id, with an absolute time window for historical alerts. */
export function wazuhAlertUrl(base: string | undefined, externalId: string, occurredAt: Date, indexPattern = "wazuh-alerts-*"): string | null {
  if (!base || !externalId || !Number.isFinite(occurredAt.getTime())) return null;
  let url: URL;
  try { url = new URL(base); } catch { return null; }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return null;
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/app/discover`;
  url.search = "";
  const query = `_id:${JSON.stringify(externalId)}`;
  const state = `(index:${risonString(indexPattern)},query:(language:lucene,query:${risonString(query)}))`;
  const from = new Date(occurredAt.getTime() - 86400_000).toISOString();
  const to = new Date(occurredAt.getTime() + 86400_000).toISOString();
  const global = `(time:(from:${risonString(from)},to:${risonString(to)}))`;
  url.hash = `/?_g=${encodeURIComponent(global)}&_a=${encodeURIComponent(state)}`;
  return url.toString();
}
