import { sql } from "drizzle-orm";
import { check, foreignKey, index, integer, jsonb, pgEnum, pgTable, primaryKey, text, timestamp, unique, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { tenants } from "./platform";

// Entity graph: see src/lib/graph. Edges and aliases reference entities by (id, tenant_id) so a row
// can never join two tenants, whatever the writer does.

export const entityType = pgEnum("entity_type", [
  "user", "identity", "device", "ip", "domain", "url", "file", "process", "cloud_resource", "indicator", "threat_actor", "campaign", "email", "alert",
]);
/** observed: a record states the relationship. inferred: blakSOC derived it (name match, co-occurrence). */
export const relationshipProvenance = pgEnum("relationship_provenance", ["observed", "inferred"]);

export const entities = pgTable(
  "entities",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    type: entityType("type").notNull(),
    /** Canonical key within (tenant, type), e.g. short hostname, lowercased user name, sha256:<hex>. */
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    identifiers: jsonb("identifiers").$type<Record<string, unknown>>().notNull().default({}),
    sourceSystems: text("source_systems").array().notNull().default([]),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex("entities_key").on(t.tenantId, t.type, t.key), unique("entities_id_tenant").on(t.id, t.tenantId)],
);

/** Alternate identifiers (MAC, asset id, UPN, FQDN…) that resolve to one entity. */
export const entityAliases = pgTable(
  "entity_aliases",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    entityId: uuid("entity_id").notNull(),
    kind: text("kind").notNull(),
    value: text("value").notNull(),
    source: text("source").notNull(),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("entity_aliases_value").on(t.tenantId, t.kind, t.value),
    index("entity_aliases_entity").on(t.entityId),
    foreignKey({ name: "entity_aliases_entity_fk", columns: [t.entityId, t.tenantId], foreignColumns: [entities.id, entities.tenantId] }).onDelete("cascade"),
  ],
);

export const entityRelationships = pgTable(
  "entity_relationships",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    fromEntityId: uuid("from_entity_id").notNull(),
    toEntityId: uuid("to_entity_id").notNull(),
    type: text("type").notNull(),
    provenance: relationshipProvenance("provenance").notNull(),
    /** Distinct evidence records behind the edge (entity_relationship_evidence rows). */
    count: integer("count").notNull().default(0),
    firstSeen: timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
    /** The record that created the edge, e.g. alert/<id>, asset/<id>, intel_match/<id>. */
    evidenceType: text("evidence_type").notNull(),
    evidenceId: text("evidence_id").notNull(),
  },
  (t) => [
    uniqueIndex("entity_relationships_unique").on(t.tenantId, t.fromEntityId, t.toEntityId, t.type),
    index("entity_relationships_from").on(t.fromEntityId, t.type),
    index("entity_relationships_to").on(t.toEntityId, t.type),
    foreignKey({ name: "entity_relationships_from_fk", columns: [t.fromEntityId, t.tenantId], foreignColumns: [entities.id, entities.tenantId] }).onDelete("cascade"),
    foreignKey({ name: "entity_relationships_to_fk", columns: [t.toEntityId, t.tenantId], foreignColumns: [entities.id, entities.tenantId] }).onDelete("cascade"),
    check("entity_relationships_no_loop", sql`${t.fromEntityId} <> ${t.toEntityId}`),
  ],
);

export const entityRelationshipEvidence = pgTable(
  "entity_relationship_evidence",
  {
    relationshipId: uuid("relationship_id").notNull().references(() => entityRelationships.id, { onDelete: "cascade" }),
    tenantId: uuid("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    evidenceType: text("evidence_type").notNull(),
    evidenceId: text("evidence_id").notNull(),
    observedAt: timestamp("observed_at", { withTimezone: true }).notNull(),
  },
  (t) => [primaryKey({ name: "entity_relationship_evidence_pk", columns: [t.relationshipId, t.evidenceType, t.evidenceId] })],
);
