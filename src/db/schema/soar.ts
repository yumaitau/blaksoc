import { boolean, index, integer, jsonb, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";
import { alerts, incidents } from "./security";

export type PlaybookTrigger = {
  event: "alert.created" | "alert.enriched" | "incident.created" | "manual";
  /** All conditions must hold. Field paths are resolved against the trigger payload. */
  conditions: { field: string; op: "eq" | "neq" | "gte" | "lte" | "in" | "contains"; value: unknown }[];
};

export type PlaybookStep = {
  id: string;
  action: string;
  name: string;
  params?: Record<string, unknown>;
  /** Only run when this condition on run context holds. */
  when?: { field: string; op: "eq" | "neq" | "gte" | "lte" | "in" | "contains"; value: unknown };
  /** Force a human gate even for non-destructive actions. */
  requireApproval?: boolean;
  continueOnError?: boolean;
};

export const playbooks = pgTable("playbooks", {
  id: uuid("id").primaryKey().defaultRandom(),
  /** Null = global template. */
  tenantId: uuid("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  description: text("description"),
  trigger: jsonb("trigger").$type<PlaybookTrigger>().notNull(),
  steps: jsonb("steps").$type<PlaybookStep[]>().notNull(),
  enabled: boolean("enabled").notNull().default(false),
  version: integer("version").notNull().default(1),
  createdBy: text("created_by"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const playbookRuns = pgTable(
  "playbook_runs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    playbookId: uuid("playbook_id").notNull().references(() => playbooks.id, { onDelete: "cascade" }),
    playbookVersion: integer("playbook_version").notNull(),
    status: text("status").notNull().default("RUNNING"), // RUNNING | WAITING_APPROVAL | SUCCEEDED | FAILED | CANCELLED
    trigger: jsonb("trigger").$type<Record<string, unknown>>().notNull(),
    context: jsonb("context").$type<Record<string, unknown>>().notNull().default({}),
    stepIndex: integer("step_index").notNull().default(0),
    alertId: uuid("alert_id").references(() => alerts.id, { onDelete: "set null" }),
    incidentId: uuid("incident_id").references(() => incidents.id, { onDelete: "set null" }),
    error: text("error"),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
  },
  (t) => [index("playbook_runs_tenant").on(t.tenantId, t.startedAt)],
);

export const playbookRunSteps = pgTable("playbook_run_steps", {
  id: uuid("id").primaryKey().defaultRandom(),
  tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
  runId: uuid("run_id").notNull().references(() => playbookRuns.id, { onDelete: "cascade" }),
  stepId: text("step_id").notNull(),
  action: text("action").notNull(),
  status: text("status").notNull(), // SKIPPED | WAITING_APPROVAL | SUCCEEDED | FAILED | REJECTED
  output: jsonb("output"),
  error: text("error"),
  approvalId: uuid("approval_id"),
  startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
});

/** Human approval gate. Every destructive action passes through one unless the tenant opted into auto-containment. */
export const approvals = pgTable(
  "approvals",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(), // playbook_step | response_action
    refId: uuid("ref_id").notNull(),
    summary: text("summary").notNull(),
    destructive: boolean("destructive").notNull(),
    requestedBy: text("requested_by"),
    requestedByKind: text("requested_by_kind").notNull(), // user | playbook | ai
    status: text("status").notNull().default("PENDING"), // PENDING | APPROVED | REJECTED | EXPIRED
    decidedBy: text("decided_by"),
    decidedAt: timestamp("decided_at", { withTimezone: true }),
    decisionNote: text("decision_note"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("approvals_pending").on(t.tenantId, t.status)],
);

/** Containment / response actions against real systems. */
export const responseActions = pgTable(
  "response_actions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    action: text("action").notNull(),
    target: jsonb("target").$type<Record<string, unknown>>().notNull(),
    destructive: boolean("destructive").notNull(),
    status: text("status").notNull(), // AWAITING_APPROVAL | APPROVED | REJECTED | EXECUTING | SUCCEEDED | FAILED
    reason: text("reason"),
    requestedBy: text("requested_by"),
    requestedByKind: text("requested_by_kind").notNull(),
    approvalId: uuid("approval_id").references(() => approvals.id),
    alertId: uuid("alert_id").references(() => alerts.id, { onDelete: "set null" }),
    incidentId: uuid("incident_id").references(() => incidents.id, { onDelete: "set null" }),
    playbookRunId: uuid("playbook_run_id").references(() => playbookRuns.id, { onDelete: "set null" }),
    integrationId: uuid("integration_id"),
    result: jsonb("result"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    executedAt: timestamp("executed_at", { withTimezone: true }),
  },
  (t) => [index("response_actions_tenant").on(t.tenantId, t.createdAt)],
);
