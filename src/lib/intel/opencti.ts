import type { IntelMatch } from "@/db/schema";
import { httpJson, type HttpOptions } from "@/lib/providers/http";
import type { Observable, ObservableType } from "./observables";
import { scoreToVerdict, type CveContext, type IntelProvider, type IntelSearchResult, type SightingInput } from "./types";

export type OpenCtiConfig = { url: string; tlsVerify?: boolean; caPem?: string };

const NAMED = `
  ... on ThreatActor { name }
  ... on IntrusionSet { name }
  ... on Malware { name }
  ... on Campaign { name }
  ... on AttackPattern { name x_mitre_id }
  ... on Indicator { name }
`;

const OBSERVABLE_LOOKUP = `
query BlakSocLookup($filters: FilterGroup, $first: Int) {
  stixCyberObservables(filters: $filters, first: $first) {
    edges { node {
      id entity_type observable_value x_opencti_score created_at updated_at
      createdBy { name }
      objectMarking { definition }
      objectLabel { value }
      indicators(first: 10) { edges { node { id name pattern x_opencti_score confidence valid_from valid_until revoked } } }
      stixCoreRelationships(first: 50) { edges { node {
        relationship_type
        from { ... on BasicObject { id entity_type } ${NAMED} }
        to { ... on BasicObject { id entity_type } ${NAMED} }
      } } }
    } }
  }
}`;

const INDICATOR_LOOKUP = `
query BlakSocIndicators($search: String, $first: Int) {
  indicators(search: $search, first: $first) {
    edges { node {
      id name pattern x_opencti_score confidence valid_from valid_until revoked created
      createdBy { name }
      objectMarking { definition }
      objectLabel { value }
      killChainPhases { kill_chain_name phase_name }
      stixCoreRelationships(first: 50) { edges { node {
        relationship_type
        to { ... on BasicObject { id entity_type } ${NAMED} }
      } } }
    } }
  }
}`;

type Named = { id?: string; entity_type?: string; name?: string; x_mitre_id?: string };
type RelEdge = { node: { relationship_type: string; from?: Named; to?: Named } };
type ObsNode = {
  id: string; entity_type: string; observable_value: string; x_opencti_score: number | null; created_at: string; updated_at: string;
  createdBy: { name: string } | null; objectMarking: { definition: string }[]; objectLabel: { value: string }[];
  indicators: { edges: { node: { id: string; name: string; pattern: string | null; x_opencti_score: number | null; confidence: number | null; revoked: boolean } }[] };
  stixCoreRelationships: { edges: RelEdge[] };
};
type IndNode = {
  id: string; name: string; pattern: string | null; x_opencti_score: number | null; confidence: number | null; valid_from: string | null;
  valid_until: string | null; revoked: boolean; created: string; createdBy: { name: string } | null; objectMarking: { definition: string }[];
  objectLabel: { value: string }[]; stixCoreRelationships: { edges: RelEdge[] };
};

function relatedNames(edges: RelEdge[]) {
  const out = { threatActors: new Set<string>(), intrusionSets: new Set<string>(), malware: new Set<string>(), campaigns: new Set<string>(), attack: new Map<string, { id: string | null; name: string }>() };
  for (const { node } of edges) {
    for (const o of [node.from, node.to]) {
      if (!o?.entity_type || !o.name) continue;
      if (o.entity_type.startsWith("Threat-Actor")) out.threatActors.add(o.name);
      else if (o.entity_type === "Intrusion-Set") out.intrusionSets.add(o.name);
      else if (o.entity_type === "Malware") out.malware.add(o.name);
      else if (o.entity_type === "Campaign") out.campaigns.add(o.name);
      else if (o.entity_type === "Attack-Pattern") out.attack.set(o.x_mitre_id ?? o.name, { id: o.x_mitre_id ?? null, name: o.name });
    }
  }
  return out;
}

/** OpenCTI is the CTI system of record; blakSOC reads and writes through its GraphQL API. */
export class OpenCtiProvider implements IntelProvider {
  readonly kind = "opencti";
  private readonly http: HttpOptions;

  constructor(private readonly cfg: OpenCtiConfig, private readonly token: string) {
    this.http = { tlsVerify: cfg.tlsVerify, caPem: cfg.caPem, timeoutMs: 15_000 };
  }

  async gql<T>(query: string, variables: Record<string, unknown> = {}): Promise<T> {
    const res = await httpJson<{ data?: T; errors?: { message: string }[] }>(
      `${this.cfg.url.replace(/\/$/, "")}/graphql`,
      { method: "POST", json: { query, variables }, headers: { authorization: `Bearer ${this.token}` } },
      this.http,
    );
    if (res.errors?.length) throw new Error(`OpenCTI: ${res.errors.map((e) => e.message).join("; ")}`);
    return res.data as T;
  }

  async lookup(observables: Observable[]): Promise<IntelMatch[]> {
    const matches: IntelMatch[] = [];
    for (const o of observables) {
      const data = await this.gql<{ stixCyberObservables: { edges: { node: ObsNode }[] } }>(OBSERVABLE_LOOKUP, {
        first: 3,
        filters: { mode: "and", filters: [{ key: "value", values: [o.value], operator: "eq", mode: "or" }], filterGroups: [] },
      });
      for (const { node } of data.stixCyberObservables.edges) {
        const rel = relatedNames(node.stixCoreRelationships.edges);
        const labels = node.objectLabel.map((l) => l.value);
        const topIndicator = node.indicators.edges.map((e) => e.node).filter((i) => !i.revoked);
        const score = node.x_opencti_score ?? topIndicator[0]?.x_opencti_score ?? null;
        matches.push({
          observable: { type: o.type, value: o.value },
          openctiId: node.id,
          entityType: node.entity_type,
          verdict: scoreToVerdict(score, topIndicator.length > 0, labels),
          score,
          confidence: topIndicator[0]?.confidence ?? null,
          source: node.createdBy?.name ?? null,
          markings: node.objectMarking.map((m) => m.definition),
          labels,
          firstSeen: node.created_at,
          lastSeen: node.updated_at,
          threatActors: [...rel.threatActors],
          intrusionSets: [...rel.intrusionSets],
          malware: [...rel.malware],
          campaigns: [...rel.campaigns],
          attackPatterns: [...rel.attack.values()],
          relatedIndicators: topIndicator.map((i) => ({ id: i.id, name: i.name, pattern: i.pattern })),
          sightings: 0,
        });
      }
      // Indicator-only intel (pattern without a materialised observable), e.g. hash feeds.
      if (!data.stixCyberObservables.edges.length && isPatternable(o.type)) {
        const ind = await this.gql<{ indicators: { edges: { node: IndNode }[] } }>(INDICATOR_LOOKUP, { search: o.value, first: 3 });
        for (const { node } of ind.indicators.edges) {
          if (node.revoked || !node.pattern?.toLowerCase().includes(o.value.toLowerCase())) continue;
          const rel = relatedNames(node.stixCoreRelationships.edges);
          const labels = node.objectLabel.map((l) => l.value);
          matches.push({
            observable: { type: o.type, value: o.value },
            openctiId: node.id,
            entityType: "Indicator",
            verdict: scoreToVerdict(node.x_opencti_score, true, labels),
            score: node.x_opencti_score,
            confidence: node.confidence,
            source: node.createdBy?.name ?? null,
            markings: node.objectMarking.map((m) => m.definition),
            labels,
            firstSeen: node.valid_from ?? node.created,
            lastSeen: node.valid_until,
            threatActors: [...rel.threatActors],
            intrusionSets: [...rel.intrusionSets],
            malware: [...rel.malware],
            campaigns: [...rel.campaigns],
            attackPatterns: [...rel.attack.values()],
            relatedIndicators: [{ id: node.id, name: node.name, pattern: node.pattern }],
            sightings: 0,
          });
        }
      }
    }
    return matches;
  }

  async cveContext(cves: string[]): Promise<CveContext[]> {
    const out: CveContext[] = [];
    for (const cve of cves) {
      const data = await this.gql<{ vulnerabilities: { edges: { node: { id: string; name: string; stixCoreRelationships: { edges: RelEdge[] } } }[] } }>(
        `query($search: String) { vulnerabilities(search: $search, first: 1) { edges { node { id name
          stixCoreRelationships(first: 100) { edges { node { relationship_type from { ... on BasicObject { id entity_type } ${NAMED} } } } } } } } }`,
        { search: cve },
      );
      const node = data.vulnerabilities.edges.find((e) => e.node.name.toUpperCase() === cve)?.node;
      const threats = (node?.stixCoreRelationships.edges ?? [])
        .map((e) => e.node.from)
        .filter((f): f is Named => !!f?.id && !!f.name && /Threat-Actor|Intrusion-Set|Malware|Campaign/.test(f.entity_type ?? ""))
        .map((f) => ({ id: f.id!, name: f.name!, type: f.entity_type! }));
      out.push({ cve, threats });
    }
    return out;
  }

  async search(term: string, types?: string[]): Promise<IntelSearchResult[]> {
    type Sdo = {
      id: string; entity_type: string; updated_at?: string; name?: string; description?: string; x_opencti_score?: number;
      createdBy?: { name: string }; objectMarking?: { definition: string }[]; objectLabel?: { value: string }[];
    };
    const data = await this.gql<{ stixDomainObjects: { edges: { node: Sdo }[] } }>(
      `query($search: String, $types: [String]) { stixDomainObjects(search: $search, types: $types, first: 25, orderBy: _score, orderMode: desc) {
        edges { node { id entity_type updated_at
          createdBy { name } objectMarking { definition } objectLabel { value }
          ... on Report { name description } ... on ThreatActor { name description } ... on IntrusionSet { name description }
          ... on Malware { name description } ... on Campaign { name description } ... on Vulnerability { name description }
          ... on AttackPattern { name description } ... on Indicator { name description x_opencti_score }
        } } } }`,
      { search: term, types: types?.length ? types : null },
    );
    return data.stixDomainObjects.edges.map(({ node }) => ({
      id: node.id,
      entityType: node.entity_type,
      name: node.name ?? node.id,
      description: node.description ?? null,
      labels: (node.objectLabel ?? []).map((l) => l.value),
      markings: (node.objectMarking ?? []).map((m) => m.definition),
      score: node.x_opencti_score ?? null,
      createdBy: node.createdBy?.name ?? null,
      modified: node.updated_at ?? null,
    }));
  }

  async createSighting(input: SightingInput) {
    const data = await this.gql<{ stixSightingRelationshipAdd: { id: string } }>(
      `mutation($input: StixSightingRelationshipAddInput!) { stixSightingRelationshipAdd(input: $input) { id } }`,
      {
        input: {
          fromId: input.openctiId,
          toId: input.whereSightedIdentityId,
          first_seen: input.firstSeen.toISOString(),
          last_seen: input.lastSeen.toISOString(),
          attribute_count: input.count,
          description: input.description,
          objectMarking: input.markingDefinitionIds,
          x_opencti_negative: false,
        },
      },
    );
    return { id: data.stixSightingRelationshipAdd.id };
  }

  async ensureIdentity(name: string, sector?: string) {
    const data = await this.gql<{ identityAdd: { id: string } }>(
      `mutation($input: IdentityAddInput!) { identityAdd(input: $input) { id } }`,
      { input: { type: sector ? "Sector" : "Organization", name, description: "blakSOC anonymised sighting source", update: true } },
    );
    return data.identityAdd.id;
  }

  async createReport(input: { name: string; description: string; published: Date; externalUrl: string; labels: string[]; cves: string[] }) {
    const data = await this.gql<{ reportAdd: { id: string } }>(
      `mutation($input: ReportAddInput!) { reportAdd(input: $input) { id } }`,
      {
        input: {
          name: input.name,
          description: input.description,
          published: input.published.toISOString(),
          report_types: ["threat-report"],
          externalReferences: [],
          objectLabel: input.labels,
          update: true,
        },
      },
    );
    return { id: data.reportAdd.id };
  }

  async addLabels(openctiId: string, labels: string[]) {
    await this.gql(
      `mutation($id: ID!, $input: [EditInput]!) { stixDomainObjectEdit(id: $id) { fieldPatch(input: $input) { id } } }`,
      { id: openctiId, input: [{ key: "objectLabel", value: labels, operation: "add" }] },
    );
  }

  async health() {
    const start = Date.now();
    try {
      const data = await this.gql<{ about: { version: string } }>(`query { about { version } }`);
      return { ok: true, latencyMs: Date.now() - start, detail: { version: data.about.version } };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - start, detail: {}, error: (err as Error).message };
    }
  }
}

function isPatternable(t: ObservableType) {
  return ["md5", "sha1", "sha256", "url", "domain", "ipv4"].includes(t);
}
