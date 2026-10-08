import { z } from "zod";
import { alertStatus, assetKind, incidentStatus, severity } from "@/db/schema";
import { PATTERN_ID } from "@/lib/tuning/pseudonym";

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
  lane: z.enum(["active", "passive"]).optional().meta({ description: "active: the triage queue; passive: known noise. Omit for both" }),
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
    lane: z.enum(["active", "passive"]),
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

// ---------------------------------------------------------------------------------------------------------------
// Tuning API (/tuning/*): aggregates and opaque ids only. Response schemas are the allow-list: a field not
// declared here never reaches the caller, whatever the service returns.

const count = z.number().int().min(0);
const confidence = z.enum(["low", "medium", "high"]);

export const PatternIdParam = z.object({ patternId: z.string().regex(PATTERN_ID).meta({ description: "Opaque pattern id from GET /tuning/patterns" }) });

export const TuningPatternsQuery = z.object({ days: z.coerce.number().int().min(1).max(90).default(7) });

const Dispositions = z.object({ falsePositive: count, resolved: count, escalated: count.meta({ description: "ESCALATED or CONTAINED" }), open: count, passive: count });

export const TuningPattern = z
  .object({
    patternId: z.string(),
    tenantRef: z.string().meta({ description: "Stable pseudonym of the tenant; never its name or id" }),
    source: z.string(),
    ruleId: z.string(),
    ruleLevel: z.number().int().meta({ description: "Wazuh rule level, else the source's native severity; 0 when unknown" }),
    ruleGroups: z.array(z.string()),
    mitre: z.array(z.string()),
    severity: z.object({ informational: count, low: count, medium: count, high: count, critical: count }),
    counts: z.object({
      total: count,
      byDay: z.array(count).meta({ description: "UTC days, oldest (partial) first, ending today; sums to total" }),
      byHourOfDay: z.array(count).length(24).meta({ description: "UTC hours 0–23" }),
    }),
    distinctAssets: count,
    distinctUsers: count,
    dispositions: z.object({ d30: Dispositions, d90: Dispositions }),
    incidentsOpened: count,
    analystOverrides: count.meta({ description: "Agent actions on this pattern analysts undid, plus alerts they reopened" }),
    medianMinutesToFirstTriage: z.number().nullable(),
    firstSeen: timestamp.nullable(),
    lastSeen: timestamp.nullable(),
    noiseRule: z.object({ id, status: z.string(), expiresAt: timestamp, hitCount: count }).nullable(),
    annotations: z.array(z.object({ confidence, createdAt: timestamp, authorKind: z.enum(["service", "user"]), text: z.string() })),
  })
  .meta({ id: "TuningPattern" });

export const TuningPatternList = z
  .object({
    windowDays: z.number().int(),
    generatedAt: timestamp,
    truncated: z.boolean(),
    patterns: z.array(TuningPattern),
    fleet: z.array(z.object({
      source: z.string(),
      ruleId: z.string(),
      tenantsAffected: count,
      total: count,
      coFiring: z
        .array(z.object({ source: z.string(), ruleId: z.string(), count, tenants: count }))
        .meta({ description: "Rules firing in the same tenant in the same UTC hour: count of such tenant-hours, distinct tenants. Top 5." }),
    })),
  })
  .meta({ id: "TuningPatternList" });

export const AnnotationCreate = z.object({ text: z.string().min(1).max(1000), confidence });
export const AnnotationResult = z.object({ id, actionId: id, createdAt: timestamp }).meta({ id: "TuningAnnotationResult" });

export const CloseRequest = z.object({
  reason: z.string().trim().min(1).max(500),
  maxAlerts: z.number().int().min(1).max(5000).optional(),
});
export const CloseResult = z.object({ actionId: id.nullable(), affected: count, reversibleUntil: timestamp.nullable() }).meta({ id: "TuningCloseResult" });

export const AgentNoiseRuleCreate = z.object({
  patternId: z.string().regex(PATTERN_ID),
  reason: z.string().trim().min(1).max(500),
  expiresInDays: z.number().int().min(1).max(30).default(30),
});
export const AgentNoiseRuleResult = z.object({ noiseRuleId: id, actionId: id, expiresAt: timestamp, movedToPassive: count }).meta({ id: "TuningNoiseRuleResult" });

export const PurgeResult = z.object({ actionId: id.nullable(), deleted: count }).meta({ id: "TuningPurgeResult" });

export const TuningActionsQuery = z.object({ since: z.iso.datetime({ offset: true }).optional().meta({ description: "Default: 7 days ago" }) });
export const TuningActionList = z
  .object({
    actions: z.array(z.object({
      id,
      kind: z.enum(["annotate", "close", "noise_rule", "purge"]),
      patternId: z.string(),
      tenantRef: z.string(),
      source: z.string(),
      ruleId: z.string(),
      createdAt: timestamp,
      affected: count,
      undoneAt: timestamp.nullable(),
      reopenedCount: count,
      status: z.enum(["applied", "undone"]),
    })),
  })
  .meta({ id: "TuningActionList" });

const ReportStats = z.object({ executed: count, refused: count, dryRun: count, patternsReviewed: count });
export const ReportCreate = z.object({
  periodStart: z.iso.datetime({ offset: true }),
  periodEnd: z.iso.datetime({ offset: true }),
  markdown: z.string().min(1).meta({ description: "Plain markdown, at most 50 KB; HTML is refused" }),
  stats: ReportStats,
});
export const ReportListQuery = z.object({ limit: limit(100, 10) });
export const ReportCreated = z.object({ id, createdAt: timestamp }).meta({ id: "HermesReportCreated" });
export const HermesReport = z.object({ id, periodStart: timestamp, periodEnd: timestamp, markdown: z.string(), stats: ReportStats, createdAt: timestamp }).meta({ id: "HermesReport" });
export const HermesReportList = z.object({ reports: z.array(HermesReport) }).meta({ id: "HermesReportList" });

const NoteKind = z.enum(["model", "outcome", "human"]);
export const HermesMemory = z
  .object({ version: count, notes: z.array(z.object({ id, kind: NoteKind, text: z.string(), createdAt: timestamp, updatedAt: timestamp })) })
  .meta({ id: "HermesMemory" });
export const MemoryPut = z.object({
  version: z.number().int().min(0).meta({ description: "The version last read; a stale one is refused with 409" }),
  notes: z
    .array(z.object({ id: z.string().max(64).nullable().optional(), kind: NoteKind, text: z.string().max(10_000) }))
    .max(2000)
    .meta({ description: "The agent's complete set of model/outcome notes (at most 500, 2000 characters each): with id updates, without id adds, omitted removes. human notes are ignored and always kept." }),
});
export const MemoryPutResult = z.object({ version: count, added: count, removed: count, changed: count, unchanged: count }).meta({ id: "HermesMemoryUpdate" });
