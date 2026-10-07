import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

/**
 * In-process stand-in for the Wazuh indexer (OpenSearch). Requests go over real HTTP through
 * egressFetch. `fakeSearch` applies the parts of a query blakSOC relies on for isolation and
 * paging: agent.id terms, ids, the timestamp range, the desc sort and search_after.
 */

export type IndexerRequest = { method: string; path: string; auth: string | undefined; body: SearchBody | undefined };
export type IndexerDoc = { _id: string; _index: string; _source: Record<string, unknown> & { timestamp: string; agent?: { id?: string; name?: string; ip?: string } } };

type Clause = Record<string, unknown>;
export type SearchBody = { size?: number; query?: { bool?: { filter?: Clause[] } }; search_after?: [string | number, string]; sort?: unknown[] };

export async function startIndexer(handler: (req: IndexerRequest) => { status?: number; body: unknown }) {
  const requests: IndexerRequest[] = [];
  const server = createServer((req, res) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      const r: IndexerRequest = { method: req.method ?? "GET", path: decodeURIComponent(req.url ?? ""), auth: req.headers.authorization, body: data ? (JSON.parse(data) as SearchBody) : undefined };
      requests.push(r);
      const out = handler(r);
      res.writeHead(out.status ?? 200, { "content-type": "application/json" });
      res.end(JSON.stringify(out.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

const clauses = (body: SearchBody | undefined) => body?.query?.bool?.filter ?? [];

export function agentTerms(body: SearchBody | undefined): string[] | undefined {
  const t = clauses(body).find((c) => c.terms) as { terms: { "agent.id": string[] } } | undefined;
  return t?.terms["agent.id"];
}

export function fakeSearch(docs: IndexerDoc[], body: SearchBody | undefined) {
  const agents = agentTerms(body);
  const ids = (clauses(body).find((c) => c.ids) as { ids: { values: string[] } } | undefined)?.ids.values;
  const range = (clauses(body).find((c) => c.range && (c.range as Clause).timestamp) as { range: { timestamp: { gte: string; lte: string } } } | undefined)?.range.timestamp;
  const key = (d: IndexerDoc): [number, string] => [Date.parse(d._source.timestamp), d._id];
  let matched = docs
    .filter((d) => !agents || agents.includes(d._source.agent?.id ?? ""))
    .filter((d) => !ids || ids.includes(d._id))
    .filter((d) => !range || (d._source.timestamp >= range.gte && d._source.timestamp <= range.lte))
    .sort((a, b) => key(b)[0] - key(a)[0] || (a._id < b._id ? 1 : -1));
  const after = body?.search_after;
  if (after) matched = matched.filter((d) => key(d)[0] < Number(after[0]) || (key(d)[0] === Number(after[0]) && d._id < String(after[1])));
  const size = body?.size ?? 10;
  return {
    timed_out: false,
    _shards: { failed: 0 },
    hits: { total: { value: matched.length }, hits: matched.slice(0, size).map((d) => ({ ...d, sort: key(d) })) },
  };
}
