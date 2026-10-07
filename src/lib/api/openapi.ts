import { z } from "zod";
import { PERMISSIONS, type Permission } from "@/lib/auth/permissions";
import * as S from "./schemas";
import { TOKEN_TTL_SECONDS } from "./tokens";

type Operation = {
  method: "get" | "post";
  path: string;
  operationId: string;
  summary: string;
  scope?: Permission;
  params?: z.ZodObject;
  query?: z.ZodObject;
  body?: z.ZodType;
  bodyType?: "application/json" | "application/x-www-form-urlencoded";
  response: z.ZodType;
  status?: number;
};

/** Every /api/v1 operation. A route added without an entry here is missing from the published document. */
export const OPERATIONS: Operation[] = [
  {
    method: "post", path: "/oauth/token", operationId: "issueToken", bodyType: "application/x-www-form-urlencoded",
    summary: `Exchange service identity client credentials for a bearer token valid for ${TOKEN_TTL_SECONDS / 60} minutes (client_credentials grant). Client authentication by HTTP Basic or form fields.`,
    body: S.TokenRequest, response: S.TokenResponse,
  },
  { method: "get", path: "/alerts", operationId: "listAlerts", summary: "Alerts in the identity's tenant scope, highest risk first", scope: "alert:read", query: S.AlertListQuery, response: S.AlertList },
  { method: "get", path: "/alerts/{id}", operationId: "getAlert", summary: "One alert with its observables", scope: "alert:read", params: S.IdParam, response: S.Alert },
  { method: "get", path: "/incidents", operationId: "listIncidents", summary: "Incidents in the identity's tenant scope, most recently updated first", scope: "incident:read", query: S.IncidentListQuery, response: S.IncidentList },
  { method: "get", path: "/incidents/{id}", operationId: "getIncident", summary: "One incident with its alerts and notes", scope: "incident:read", params: S.IdParam, response: S.Incident },
  { method: "post", path: "/incidents/{id}/notes", operationId: "addIncidentNote", summary: "Add a note to an incident", scope: "incident:write", params: S.IdParam, body: S.NoteCreate, response: S.IncidentNote, status: 201 },
  { method: "get", path: "/assets", operationId: "listAssets", summary: "Assets in the identity's tenant scope, highest risk first", scope: "asset:read", query: S.AssetListQuery, response: S.AssetList },
];

// Zod emits a regex beside each format; the format alone reads better and validators know it.
const override = ({ jsonSchema }: { jsonSchema: { format?: string; pattern?: string } }) => {
  if (jsonSchema.format) delete jsonSchema.pattern;
};

const ref = (id: string) => ({ $ref: `#/components/schemas/${id}` });

function strip<T extends Record<string, unknown>>(schema: T): Omit<T, "$schema" | "$id"> {
  const { $schema: _s, $id: _i, ...rest } = schema;
  return rest;
}

/** Named schemas become components; request bodies are inlined in their input shape. */
function schemaFor(schema: z.ZodType, io: "input" | "output") {
  const id = z.globalRegistry.get(schema)?.id;
  if (id) return ref(id);
  return strip(z.toJSONSchema(schema, { io, override }) as Record<string, unknown>);
}

function parameters(obj: z.ZodObject | undefined, where: "path" | "query") {
  if (!obj) return [];
  const json = z.toJSONSchema(obj, { io: "input", override }) as { properties?: Record<string, { description?: string }>; required?: string[] };
  return Object.entries(json.properties ?? {}).map(([name, s]) => {
    const { description, ...schema } = s;
    return { name, in: where, required: where === "path" || !!json.required?.includes(name), ...(description ? { description } : {}), schema };
  });
}

const errors = (op: Operation) => {
  const e = { content: { "application/json": { schema: ref("Error") } } };
  if (!op.scope) return { "400": { description: "invalid_request or unsupported_grant_type", ...e }, "401": { description: "invalid_client", ...e }, "429": { description: "Rate limited", ...e } };
  return {
    "400": { description: "Invalid parameters", ...e },
    "401": { description: "Missing, expired or revoked token", ...e },
    "403": { description: "The identity lacks the scope, or the resource is outside its tenant", ...e },
    ...(op.params ? { "404": { description: "Not found in the identity's scope", ...e } } : {}),
    "429": { description: "Per-identity rate limit exceeded; see Retry-After", ...e },
  };
};

/** Stable serialisation for docs/openapi.json. */
export const openApiJson = () => `${JSON.stringify(openApiDocument(), null, 2)}\n`;

export function openApiDocument() {
  const components = z.toJSONSchema(z.globalRegistry, { io: "output", override, uri: (id) => `#/components/schemas/${id}` }).schemas;
  const paths: Record<string, Record<string, unknown>> = {};
  for (const op of OPERATIONS) {
    paths[op.path] ??= {};
    paths[op.path]![op.method] = {
      operationId: op.operationId,
      summary: op.summary,
      ...(op.scope ? { security: [{ oauth2: [op.scope] }] } : { security: [] }),
      parameters: [...parameters(op.params, "path"), ...parameters(op.query, "query")],
      ...(op.body ? { requestBody: { required: true, content: { [op.bodyType ?? "application/json"]: { schema: schemaFor(op.body, "input") } } } } : {}),
      responses: {
        [String(op.status ?? 200)]: { description: "OK", content: { "application/json": { schema: schemaFor(op.response, "output") } } },
        ...errors(op),
      },
    };
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "blakSOC API",
      version: "1.0.0",
      description:
        "Versioned REST API for service identities. Every call runs through the same permission checks, tenant row-level security and tamper-evident audit trail as the web app, with the service identity as the actor.",
    },
    servers: [{ url: "/api/v1" }],
    security: [{ oauth2: [] }],
    paths,
    components: {
      securitySchemes: {
        oauth2: {
          type: "oauth2",
          description: "Scopes are blakSOC permissions. A token carries every scope its identity holds; an identity never holds more than its creator.",
          flows: { clientCredentials: { tokenUrl: "/api/v1/oauth/token", scopes: Object.fromEntries(PERMISSIONS.map((p) => [p, p])) } },
        },
      },
      schemas: Object.fromEntries(Object.entries(components).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, strip(v as Record<string, unknown>)])),
    },
  };
}
