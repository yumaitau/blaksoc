import { and, asc, eq, inArray, lte } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { systemDb } from "@/db/client";
import { withScope } from "@/db/scope";
import { approvals, assets, dfirCollections, dfirHunts, evidence, incidents, integrations } from "@/db/schema";
import { audit } from "@/lib/audit";
import type { AccessContext } from "@/lib/auth/access";
import { systemScope } from "@/lib/auth/access";
import { requireCapability } from "@/lib/services/billing";
import { artifactDigest, assertFixtureMode, huntMatch, renderCustody, storageUri } from "@/lib/dfir/fixture";
import { ARTIFACT_LABELS, isArtifactSet, LOW_BANDWIDTH_DELAY_MS, LOW_BANDWIDTH_HOSTS } from "@/lib/dfir/sets";
import { addTimeline } from "./incidents";
import { actor, AccessDenied, inTenant, scoped } from "./common";

type Who = { userId: string | null; name: string; kind: "user" | "system" };
type Collection = typeof dfirCollections.$inferSelect;

async function velociraptorRow(tx: Tx, tenantId: string) {
  const [row] = await tx
    .select({ id: integrations.id, config: integrations.config })
    .from(integrations)
    .where(and(eq(integrations.provider, "velociraptor"), eq(integrations.tenantId, tenantId), eq(integrations.enabled, true)));
  if (!row) throw new Error("Add a Velociraptor connector for this customer first.");
  assertFixtureMode(row.config.mode);
  return row;
}

async function attachResults(tx: Tx, col: Collection, who: Who, now: Date) {
  const hosts = await tx
    .select({ id: assets.id, name: assets.name, hostname: assets.hostname })
    .from(assets)
    .where(and(eq(assets.tenantId, col.tenantId), inArray(assets.id, col.assetIds)));
  if (hosts.length !== col.assetIds.length) throw new Error("collection asset missing");
  const sets = col.artifactSets.filter(isArtifactSet);
  for (const asset of hosts) {
    for (const set of sets) {
      const uri = storageUri(col.id, asset.id, set);
      const [existing] = await tx.select({ id: evidence.id }).from(evidence).where(eq(evidence.storageUri, uri));
      if (existing) continue;
      const name = `${ARTIFACT_LABELS[set]} · ${asset.hostname ?? asset.name}`;
      const digest = artifactDigest(set, asset);
      const [saved] = await tx
        .insert(evidence)
        .values({
          tenantId: col.tenantId,
          incidentId: col.incidentId,
          name,
          kind: `velociraptor_${set}`,
          sha256: digest,
          storageUri: uri,
          description: `Velociraptor ${ARTIFACT_LABELS[set]} for ${asset.hostname ?? asset.name}`,
          collectedBy: who.name,
          collectedAt: now,
        })
        .returning();
      await addTimeline(tx, {
        tenantId: col.tenantId,
        incidentId: col.incidentId,
        origin: who.kind === "user" ? "analyst" : "machine",
        category: "analyst",
        title: `Evidence added: ${name}`,
        detail: `sha256 ${digest}`,
        actorId: who.userId,
        refType: "evidence",
        refId: saved!.id,
      });
      await audit(tx, {
        actorId: who.userId,
        actorKind: who.kind,
        tenantId: col.tenantId,
        action: "incident.evidence_add",
        targetType: "incident",
        targetId: col.incidentId,
        detail: { evidenceId: saved!.id, name, sha256: digest, collectionId: col.id },
      });
    }
  }
  const [done] = await tx.update(dfirCollections).set({ status: "complete", approvedBy: col.approvedBy ?? who.name }).where(eq(dfirCollections.id, col.id)).returning();
  await audit(tx, {
    actorId: who.userId,
    actorKind: who.kind,
    tenantId: col.tenantId,
    action: "dfir.collection_complete",
    targetType: "dfir_collection",
    targetId: col.id,
    detail: { incidentId: col.incidentId },
  });
  return done!;
}

export async function listCollections(ctx: AccessContext, incidentId: string) {
  return scoped(ctx, "incident:read", (tx, tenantIds) =>
    tx
      .select()
      .from(dfirCollections)
      .where(and(eq(dfirCollections.incidentId, incidentId), inArray(dfirCollections.tenantId, tenantIds)))
      .orderBy(asc(dfirCollections.createdAt)),
  );
}

export async function listCollectionTargets(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "incident:read", tenantId, (tx) =>
    tx
      .select({ id: assets.id, name: assets.name, hostname: assets.hostname })
      .from(assets)
      .where(and(eq(assets.tenantId, tenantId), eq(assets.kind, "endpoint")))
      .orderBy(assets.name)
      .limit(200),
  );
}

export async function requestCollection(
  ctx: AccessContext,
  incidentId: string,
  input: { assetIds: string[]; artifactSets: string[]; lowBandwidth: boolean; now?: Date },
) {
  const inc = await scoped(ctx, "incident:read", async (tx, tenantIds) =>
    (await tx.select().from(incidents).where(and(eq(incidents.id, incidentId), inArray(incidents.tenantId, tenantIds))))[0],
  );
  if (!inc) throw new AccessDenied("incident not found");
  const sets = input.artifactSets.filter(isArtifactSet);
  if (!sets.length || sets.length !== input.artifactSets.length) throw new Error("Pick at least one artifact set.");
  if (!input.assetIds.length) throw new Error("Pick at least one machine.");
  if (input.lowBandwidth && input.assetIds.length > LOW_BANDWIDTH_HOSTS) {
    throw new Error(`Low bandwidth collections cover at most ${LOW_BANDWIDTH_HOSTS} machines.`);
  }
  const now = input.now ?? new Date();
  return inTenant(ctx, "incident:write", inc.tenantId, async (tx) => {
    await requireCapability(tx, inc.tenantId, "velociraptor_dfir");
    await velociraptorRow(tx, inc.tenantId);
    const hosts = await tx
      .select({ id: assets.id })
      .from(assets)
      .where(and(eq(assets.tenantId, inc.tenantId), eq(assets.kind, "endpoint"), inArray(assets.id, input.assetIds)));
    if (hosts.length !== input.assetIds.length) throw new AccessDenied("asset not in this tenant");
    const notBefore = new Date(now.getTime() + (input.lowBandwidth ? LOW_BANDWIDTH_DELAY_MS : 0));
    const [col] = await tx
      .insert(dfirCollections)
      .values({
        tenantId: inc.tenantId,
        incidentId,
        assetIds: input.assetIds,
        artifactSets: sets,
        lowBandwidth: input.lowBandwidth,
        status: "pending_approval",
        notBefore,
        requestedBy: ctx.principal.userId,
      })
      .returning();
    const [ap] = await tx
      .insert(approvals)
      .values({
        tenantId: inc.tenantId,
        kind: "dfir_collection",
        refId: col!.id,
        summary: `Collect ${sets.map((s) => ARTIFACT_LABELS[s]).join(", ")} from ${input.assetIds.length} machine${input.assetIds.length === 1 ? "" : "s"}`,
        destructive: true,
        requestedBy: ctx.principal.userId,
        requestedByKind: "user",
        expiresAt: new Date(now.getTime() + 24 * 3600_000),
      })
      .returning();
    await tx.update(dfirCollections).set({ approvalId: ap!.id }).where(eq(dfirCollections.id, col!.id));
    await addTimeline(tx, {
      tenantId: inc.tenantId,
      incidentId,
      origin: "analyst",
      category: "response",
      title: "Collection requested",
      detail: sets.map((s) => ARTIFACT_LABELS[s]).join(", "),
      actorId: ctx.principal.userId,
      refType: "dfir_collection",
      refId: col!.id,
    });
    await audit(tx, {
      ...actor(ctx),
      tenantId: inc.tenantId,
      action: "dfir.collection_request",
      targetType: "dfir_collection",
      targetId: col!.id,
      detail: { incidentId, artifactSets: sets, lowBandwidth: input.lowBandwidth, approvalId: ap!.id },
    });
    return { ...col!, approvalId: ap!.id };
  });
}

/** Called when the collection's approval lapsed with no decision. Nothing is collected. */
export async function expireDfirApproval(tx: Tx, collectionId: string) {
  const [col] = await tx.update(dfirCollections).set({ status: "rejected" }).where(and(eq(dfirCollections.id, collectionId), eq(dfirCollections.status, "pending_approval"))).returning();
  if (!col) return null;
  await addTimeline(tx, { tenantId: col.tenantId, incidentId: col.incidentId, origin: "machine", category: "response", title: "Collection approval expired without a decision", refType: "dfir_collection", refId: col.id });
  return col;
}

/** Called from the approval decision, inside that transaction. */
export async function settleDfirApproval(tx: Tx, collectionId: string, decision: "APPROVED" | "REJECTED", who: { userId: string; name: string }, now: Date) {
  const [col] = await tx.select().from(dfirCollections).where(eq(dfirCollections.id, collectionId));
  if (!col) throw new Error("collection not found");
  if (decision === "REJECTED") {
    const [row] = await tx.update(dfirCollections).set({ status: "rejected", approvedBy: who.name }).where(eq(dfirCollections.id, col.id)).returning();
    await addTimeline(tx, {
      tenantId: col.tenantId,
      incidentId: col.incidentId,
      origin: "analyst",
      category: "response",
      title: `Collection rejected by ${who.name}`,
      actorId: who.userId,
      refType: "dfir_collection",
      refId: col.id,
    });
    return row!;
  }
  const approved = { ...col, approvedBy: who.name };
  if (col.notBefore.getTime() > now.getTime()) {
    const [row] = await tx.update(dfirCollections).set({ status: "scheduled", approvedBy: who.name }).where(eq(dfirCollections.id, col.id)).returning();
    await addTimeline(tx, {
      tenantId: col.tenantId,
      incidentId: col.incidentId,
      origin: "analyst",
      category: "response",
      title: `Collection approved. Upload waits until ${col.notBefore.toISOString()}`,
      actorId: who.userId,
      refType: "dfir_collection",
      refId: col.id,
    });
    return row!;
  }
  return attachResults(tx, approved, { userId: who.userId, name: who.name, kind: "user" }, now);
}

/** Release scheduled uploads for one tenant. Tests call this, not the all-tenant sweep. */
export async function releaseScheduledCollection(tenantId: string, now = new Date()) {
  return withScope(systemScope(tenantId), async (tx) => {
    const due = await tx
      .select()
      .from(dfirCollections)
      .where(and(eq(dfirCollections.tenantId, tenantId), eq(dfirCollections.status, "scheduled"), lte(dfirCollections.notBefore, now)));
    let count = 0;
    for (const col of due) {
      await attachResults(tx, col, { userId: null, name: col.approvedBy ?? "Velociraptor", kind: "system" }, now);
      count += 1;
    }
    return count;
  });
}

/** Worker sweep. One tenant at a time so a failure does not stop the others. */
export async function releaseDueCollections(now = new Date()) {
  const due = await systemDb()
    .selectDistinct({ tenantId: dfirCollections.tenantId })
    .from(dfirCollections)
    .where(and(eq(dfirCollections.status, "scheduled"), lte(dfirCollections.notBefore, now)));
  const released: string[] = [];
  for (const row of due) {
    try {
      const count = await releaseScheduledCollection(row.tenantId, now);
      if (count) released.push(row.tenantId);
    } catch (err) {
      console.error(`[dfir] release ${row.tenantId} failed: ${(err as Error).message}`);
    }
  }
  return released;
}

export async function startHunt(ctx: AccessContext, incidentId: string, ioc: string) {
  const needle = ioc.trim();
  if (!needle) throw new Error("Indicator is empty.");
  const inc = await scoped(ctx, "incident:read", async (tx, tenantIds) =>
    (await tx.select().from(incidents).where(and(eq(incidents.id, incidentId), inArray(incidents.tenantId, tenantIds))))[0],
  );
  if (!inc) throw new AccessDenied("incident not found");
  return inTenant(ctx, "incident:write", inc.tenantId, async (tx) => {
    await requireCapability(tx, inc.tenantId, "velociraptor_dfir");
    await velociraptorRow(tx, inc.tenantId);
    const fleet = await tx
      .select({ id: assets.id, hostname: assets.hostname, name: assets.name, ips: assets.ips })
      .from(assets)
      .where(and(eq(assets.tenantId, inc.tenantId), eq(assets.kind, "endpoint")));
    const matched = fleet.filter((asset) => huntMatch(asset, needle));
    const [hunt] = await tx
      .insert(dfirHunts)
      .values({ tenantId: inc.tenantId, incidentId, ioc: needle, status: "complete", matchedAssetIds: matched.map((asset) => asset.id) })
      .returning();
    await audit(tx, {
      ...actor(ctx),
      tenantId: inc.tenantId,
      action: "dfir.hunt",
      targetType: "dfir_hunt",
      targetId: hunt!.id,
      detail: { incidentId, ioc: needle, matches: matched.length },
    });
    return { id: hunt!.id, matchedAssetIds: hunt!.matchedAssetIds };
  });
}

export async function custodyExport(ctx: AccessContext, incidentId: string) {
  return scoped(ctx, "incident:read", async (tx, tenantIds) => {
    const [inc] = await tx
      .select({ ref: incidents.ref })
      .from(incidents)
      .where(and(eq(incidents.id, incidentId), inArray(incidents.tenantId, tenantIds)));
    if (!inc) throw new AccessDenied("incident not found");
    const rows = await tx.select().from(evidence).where(eq(evidence.incidentId, incidentId)).orderBy(asc(evidence.collectedAt));
    return renderCustody(inc.ref, rows);
  });
}
