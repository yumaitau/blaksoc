import { z } from "zod";
import { alertStatus, assetKind, incidentStatus, severity } from "@/db/schema";

/**
 * /api/v1 wire contract. Inputs are parsed with these schemas; outputs are passed through them
 * (unknown fields stripped), so the OpenAPI document generated from them is what clients get.
 */

const id = z.uuid();
const timestamp = z.iso.datetime({ offset: true });
const Severity = z.enum(severity.enumValues);
const AlertStatus = z.enum(alertStatus.enumValues);
const IncidentStatus = z.enum(incidentStatus.enumValues);
const AssetKind = z.enum(assetKind.enumValues);

/** Comma-separated list in a query string, e.g. `status=NEW,TRIAGING`. */
const csv = <const V extends readonly [string, ...string[]]>(values: V) =>
  z
    .string()
    .transform((s) => s.split(",").map((v) => v.trim()).filter(Boolean))
    .pipe(z.array(z.enum(values)))
    .meta({ description: `Comma-separated, any of: ${values.join(", ")}` });
const limit = (max: number, fallback: number) => z.coerce.number().int().min(1).max(max).default(fallback);

export const IdParam = z.object({ id: id.meta({ description: "Resource id" }) });

export const ErrorBody = z
  .object({
    error: z.string().meta({ description: "Machine-readable code, e.g. invalid_token, insufficient_scope, not_found" }),
    message: z.string().optional(),
    issues: z.array(z.object({ path: z.string(), message: z.string() })).optional(),
  })
  .meta({ id: "Error" });

/** Request bodies are documented inline with their input shape (defaults optional). */
export const TokenRequest = z.object({
  grant_type: z.literal("client_credentials"),
  client_id: id.optional().meta({ description: "Omit when using HTTP Basic client authentication" }),
  client_secret: z.string().optional(),
});

export const TokenResponse = z
  .object({
    access_token: z.string(),
    token_type: z.literal("Bearer"),
    expires_in: z.number().int(),
    scope: z.string().meta({ description: "Space-separated permissions the token carries" }),
  })
  .meta({ id: "TokenResponse" });

export const AlertListQuery = z.object({
  tenantId: id.optional().meta({ description: "Restrict to one tenant in the identity's scope" }),
  status: csv(alertStatus.enumValues).optional(),
  severity: csv(severity.enumValues).optional(),
  sinceHours: z.coerce.number().int().min(1).max(24 * 365).optional(),
  limit: limit(500, 100),
  offset: z.coerce.number().int().min(0).default(0),
});

export const AlertSummary = z
  .object({
    id,
    tenantId: id,
    tenantName: z.string(),
    title: z.string(),
    severity: Severity,
    riskScore: z.number().int(),
    status: AlertStatus,
    source: z.string(),
    category: z.string().nullable(),
    assetId: id.nullable(),
    assetName: z.string().nullable(),
    userName: z.string().nullable(),
    intelVerdict: z.string(),
    attackTechniques: z.array(z.string()),
    occurredAt: timestamp,
    incidentId: id.nullable(),
  })
  .meta({ id: "AlertSummary" });

export const AlertList = z.object({ data: z.array(AlertSummary), total: z.number().int() }).meta({ id: "AlertList" });

export const Alert = z
  .object({
    id,
    tenantId: id,
    tenantName: z.string(),
    title: z.string(),
    description: z.string().nullable(),
    severity: Severity,
    riskScore: z.number().int(),
    status: AlertStatus,
    source: z.string(),
    category: z.string().nullable(),
    assetId: id.nullable(),
    userName: z.string().nullable(),
    intelVerdict: z.string(),
    attackTechniques: z.array(z.string()),
    occurredAt: timestamp,
    ingestedAt: timestamp,
    incidentId: id.nullable(),
    observables: z.array(z.object({ type: z.string(), value: z.string(), verdict: z.string(), field: z.string().nullable() })),
  })
  .meta({ id: "Alert" });

export const IncidentListQuery = z.object({
  tenantId: id.optional().meta({ description: "Restrict to one tenant in the identity's scope" }),
  status: csv(incidentStatus.enumValues).optional(),
  open: z.enum(["true", "false"]).transform((v) => v === "true").optional().meta({ description: "true: everything not CLOSED" }),
  limit: limit(500, 200),
});

export const IncidentSummary = z
  .object({
    id,
    ref: z.number().int(),
    tenantId: id,
    tenantName: z.string(),
    title: z.string(),
    severity: Severity,
    status: IncidentStatus,
    riskScore: z.number().int(),
    ownerName: z.string().nullable(),
    alertCount: z.number().int(),
    attackTechniques: z.array(z.string()),
    slaDueAt: timestamp.nullable(),
    createdAt: timestamp,
    updatedAt: timestamp,
  })
  .meta({ id: "IncidentSummary" });

export const IncidentList = z.object({ data: z.array(IncidentSummary) }).meta({ id: "IncidentList" });

export const IncidentNote = z
  .object({
    id,
    body: z.string(),
    visibility: z.enum(["internal", "customer"]),
    aiGenerated: z.boolean(),
    authorName: z.string().nullable().meta({ description: "Null when a service identity wrote the note" }),
    createdAt: timestamp,
  })
  .meta({ id: "IncidentNote" });

export const Incident = z
  .object({
    id,
    ref: z.number().int(),
    tenantId: id,
    tenantName: z.string(),
    title: z.string(),
    description: z.string().nullable(),
    severity: Severity,
    status: IncidentStatus,
    riskScore: z.number().int(),
    ownerName: z.string().nullable(),
    attackTechniques: z.array(z.string()),
    slaDueAt: timestamp.nullable(),
    createdAt: timestamp,
    updatedAt: timestamp,
    containedAt: timestamp.nullable(),
    closedAt: timestamp.nullable(),
    alerts: z.array(z.object({ id, title: z.string(), severity: Severity, status: AlertStatus, riskScore: z.number().int(), occurredAt: timestamp })),
    notes: z.array(IncidentNote),
  })
  .meta({ id: "Incident" });

export const NoteCreate = z.object({
  body: z.string().trim().min(1).max(10_000),
  visibility: z.enum(["internal", "customer"]).default("internal").meta({ description: "customer notes appear in the customer portal" }),
});

export const AssetListQuery = z.object({
  tenantId: id.optional().meta({ description: "Restrict to one tenant in the identity's scope" }),
  kind: AssetKind.optional(),
  q: z.string().trim().min(1).max(200).optional().meta({ description: "Name, hostname or exact IP" }),
  limit: limit(1000, 500),
});

export const Asset = z
  .object({
    id,
    tenantId: id,
    tenantName: z.string(),
    kind: AssetKind,
    name: z.string(),
    hostname: z.string().nullable(),
    ips: z.array(z.string()),
    os: z.string().nullable(),
    owner: z.string().nullable(),
    criticality: z.number().int(),
    exposure: z.string(),
    riskScore: z.number().int(),
    lastSeen: timestamp,
    openAlerts: z.number().int(),
    openVulns: z.number().int(),
  })
  .meta({ id: "Asset" });

export const AssetList = z.object({ data: z.array(Asset) }).meta({ id: "AssetList" });
