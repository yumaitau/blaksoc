import { index, integer, pgTable, primaryKey, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

/** One replay of a training scenario by one trainee. */
export const trainingAttempts = pgTable(
  "training_attempts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    scenarioId: text("scenario_id").notNull(),
    traineeId: text("trainee_id").notNull(),
    traineeName: text("trainee_name").notNull(),
    actions: text("actions").array().notNull().default([]),
    hintsUsed: integer("hints_used").notNull().default(0),
    score: integer("score").notNull().default(0),
    status: text("status").notNull().default("open"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("training_attempts_tenant").on(t.tenantId, t.traineeId)],
);

/** Mentor approval to shadow a real queue. This row does not grant a tenant role. */
export const trainingCosigns = pgTable(
  "training_cosigns",
  {
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    traineeId: text("trainee_id").notNull(),
    mentorId: text("mentor_id").notNull(),
    cosignedAt: timestamp("cosigned_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.tenantId, t.traineeId] })],
);
