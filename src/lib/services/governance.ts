import { and, desc, eq, inArray } from "drizzle-orm";
import { z } from "zod";
import { systemDb, type DbOrTx, type Tx } from "@/db/client";
import { withScope } from "@/db/scope";
import {
  AI_CAPABILITIES, dataGovernance, governanceChanges, integrations, MOST_PROTECTIVE, notificationDeliveries, roleAssignments, roles, tenants, user,
  type GovernanceProfile,
} from "@/db/schema";
import { can, systemScope, type AccessContext } from "@/lib/auth/access";
import { audit } from "@/lib/audit";
import { notifier } from "@/lib/connectors/instances";
import { env } from "@/lib/env";
import { approvalsRequired, describeProfile, diffProfile } from "@/lib/governance/policy";
import { actor, AccessDenied } from "./common";

export const STEWARD_ROLE = "data_steward";

export class GovernanceError extends Error {
  readonly code: "invalid" | "unchanged" | "closed" | "self" | "twice";
  constructor(code: GovernanceError["code"]) {
    super(code);
    this.name = "GovernanceError";
    this.code = code;
  }
}

/** The enforced profile. No row means the most protective profile. */
export async function governanceProfile(tx: DbOrTx, tenantId: string): Promise<GovernanceProfile> {
  const [row] = await tx.select({ profile: dataGovernance.profile }).from(dataGovernance).where(eq(dataGovernance.tenantId, tenantId));
  return row?.profile ?? MOST_PROTECTIVE;
}

/** Owner-connection read for the worker and other system paths. */
export async function governanceFor(tenantId: string): Promise<GovernanceProfile> {
  return governanceProfile(systemDb(), tenantId);
}

/** A steward holds the role directly on this tenant. Platform staff and partner reach never count. */
export function isSteward(ctx: AccessContext, tenantId: string): boolean {
  return !ctx.isPlatform && ctx.grants.some((g) => g.roleKey === STEWARD_ROLE && g.tenantId === tenantId);
}

/** Steward user ids for a tenant. Users who also hold a platform role are excluded. */
export async function stewardIds(tenantId: string): Promise<string[]> {
  const rows = await systemDb()
    .select({ userId: roleAssignments.userId })
    .from(roleAssignments)
    .where(and(eq(roleAssignments.roleKey, STEWARD_ROLE), eq(roleAssignments.tenantId, tenantId)));
  const ids = [...new Set(rows.map((r) => r.userId))];
  if (!ids.length) return [];
  const platform = await systemDb()
    .select({ userId: roleAssignments.userId })
    .from(roleAssignments)
    .innerJoin(roles, eq(roles.key, roleAssignments.roleKey))
    .where(and(inArray(roleAssignments.userId, ids), eq(roles.scope, "platform")));
  const staff = new Set(platform.map((r) => r.userId));
  return ids.filter((id) => !staff.has(id));
}

export async function userHoldsPlatformRole(userId: string): Promise<boolean> {
  const rows = await systemDb()
    .select({ key: roleAssignments.roleKey })
    .from(roleAssignments)
    .innerJoin(roles, eq(roles.key, roleAssignments.roleKey))
    .where(and(eq(roleAssignments.userId, userId), eq(roles.scope, "platform")))
    .limit(1);
  return rows.length > 0;
}

const proposalSchema = z.object({
  residencyLock: z.boolean(),
  sightings: z.object({ attribution: z.enum(["anonymised", "named"]), maxTlp: z.enum(["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]) }).nullable(),
  ai: z.object(Object.fromEntries(AI_CAPABILITIES.map((k) => [k, z.boolean()])) as Record<(typeof AI_CAPABILITIES)[number], z.ZodBoolean>),
});

export type GovernanceProposal = z.infer<typeof proposalSchema>;

function assertSteward(ctx: AccessContext, tenantId: string) {
  if (!isSteward(ctx, tenantId)) throw new AccessDenied("data steward required");
}

/** Who can read the profile: anyone working on or in the tenant. */
function assertReader(ctx: AccessContext, tenantId: string) {
  if (!ctx.tenantIds.includes(tenantId) || !(can(ctx, "portal:read", tenantId) || can(ctx, "dashboard:read", tenantId))) throw new AccessDenied("tenant");
}

export async function governanceView(ctx: AccessContext, tenantId: string) {
  assertReader(ctx, tenantId);
  const stewards = await stewardIds(tenantId);
  return withScope(systemScope(tenantId), async (tx) => {
    const profile = await governanceProfile(tx, tenantId);
    const changes = await tx.select().from(governanceChanges).where(eq(governanceChanges.tenantId, tenantId)).orderBy(desc(governanceChanges.createdAt)).limit(20);
    return { profile, sentences: describeProfile(profile), stewards: stewards.length, changes, steward: isSteward(ctx, tenantId) };
  });
}

/** Sightings consent keeps its original record when the scope does not change. Apply fills in new consent. */
function nextProfile(before: GovernanceProfile, input: GovernanceProposal): GovernanceProfile {
  const sightings = input.sightings ? { ...input.sightings, consentedBy: [], consentedAt: "" } : null;
  const after: GovernanceProfile = { residencyLock: input.residencyLock, sightings, ai: { ...input.ai } };
  if (sameScope(before, after)) after.sightings = before.sightings;
  return after;
}

/** Email every steward and record each delivery. A missing email connector is recorded as a failed delivery. */
export async function notifyStewards(tx: Tx, tenantId: string, target: { type: string; id: string }, title: string, summary: string) {
  const ids = await stewardIds(tenantId);
  const people = ids.length ? await systemDb().select({ id: user.id, email: user.email }).from(user).where(inArray(user.id, ids)) : [];
  const [tenant] = await tx.select({ name: tenants.name }).from(tenants).where(eq(tenants.id, tenantId));
  const [row] = await tx.select().from(integrations).where(and(eq(integrations.tenantId, tenantId), eq(integrations.enabled, true), eq(integrations.provider, "email")));
  for (const person of people) {
    let status: "sent" | "failed" = "failed";
    let providerRef: string | null = null;
    let detail = "no email connector";
    if (row) {
      try {
        const sent = await notifier(row)?.deliver({
          event: "governance.change",
          tenant: { id: tenantId, name: tenant?.name ?? "Customer" },
          title,
          url: `${env().APP_URL}/portal/governance`,
          summary,
          to: person.email,
        });
        if (sent) ({ status, providerRef, detail } = sent);
        else detail = "connector is not a notifier";
      } catch (err) {
        detail = err instanceof Error ? err.message : "send failed";
      }
    }
    await tx.insert(notificationDeliveries).values({ tenantId, provider: row?.provider ?? "email", channel: "email", destination: person.email, status, providerRef, detail: { kind: "governance", target, detail } });
    await audit(tx, { actorId: null, actorKind: "system", tenantId, action: "governance.notify", targetType: target.type, targetId: target.id, detail: { steward: person.id, status } });
  }
  return people.length;
}

function sameScope(a: GovernanceProfile, b: GovernanceProfile): boolean {
  return !!a.sightings && !!b.sightings && a.sightings.attribution === b.sightings.attribution && a.sightings.maxTlp === b.sightings.maxTlp;
}

async function apply(tx: Tx, proposed: typeof governanceChanges.$inferSelect, approvals: string[], who: { actorId: string; actorKind: "user" }) {
  const now = new Date();
  // New sighting consent is recorded against every steward who approved it, at the time it took effect.
  const fresh = proposed.after.sightings && !sameScope(proposed.before, proposed.after);
  const change = fresh ? { ...proposed, after: { ...proposed.after, sightings: { ...proposed.after.sightings!, consentedBy: approvals, consentedAt: now.toISOString() } } } : proposed;
  await tx
    .insert(dataGovernance)
    .values({ tenantId: change.tenantId, profile: change.after, changeId: change.id, updatedAt: now })
    .onConflictDoUpdate({ target: dataGovernance.tenantId, set: { profile: change.after, changeId: change.id, updatedAt: now } });
  await tx.update(governanceChanges).set({ status: "applied", after: change.after, approvals, decidedBy: who.actorId, decidedAt: now }).where(eq(governanceChanges.id, change.id));
  // Other open proposals were written against the old profile.
  await tx
    .update(governanceChanges)
    .set({ status: "superseded", decidedAt: now })
    .where(and(eq(governanceChanges.tenantId, change.tenantId), eq(governanceChanges.status, "pending")));
  const diff = diffProfile(change.before, change.after);
  await audit(tx, { ...who, tenantId: change.tenantId, action: "governance.apply", targetType: "governance_change", targetId: change.id, detail: { before: change.before, after: change.after, approvals, diff } });
  await notifyStewards(tx, change.tenantId, { type: "governance_change", id: change.id }, "Data rules changed", `Now in force: ${diff.join("; ")}. Approved by ${approvals.length} steward${approvals.length === 1 ? "" : "s"}.`);
}

export async function proposeGovernanceChange(ctx: AccessContext, tenantId: string, raw: unknown, reason: string) {
  assertSteward(ctx, tenantId);
  const parsed = proposalSchema.safeParse(raw);
  const why = reason.trim().slice(0, 500);
  if (!parsed.success || !why) throw new GovernanceError("invalid");
  const required = approvalsRequired((await stewardIds(tenantId)).length);
  const who = actor(ctx);
  return withScope(systemScope(tenantId), async (tx) => {
    const before = await governanceProfile(tx, tenantId);
    const approvals = [ctx.principal.userId];
    const after = nextProfile(before, parsed.data);
    const diff = diffProfile(before, after);
    if (!diff.length) throw new GovernanceError("unchanged");
    const [change] = await tx.insert(governanceChanges).values({ tenantId, before, after, reason: why, proposedBy: ctx.principal.userId, approvals, required }).returning();
    await audit(tx, { ...who, tenantId, action: "governance.propose", targetType: "governance_change", targetId: change!.id, detail: { diff, required, reason: why } });
    if (required <= 1) await apply(tx, change!, approvals, who);
    else await notifyStewards(tx, tenantId, { type: "governance_change", id: change!.id }, "Data rules change waiting", `${ctx.principal.name} asked for: ${diff.join("; ")}. A second steward must approve it.`);
    const [saved] = await tx.select().from(governanceChanges).where(eq(governanceChanges.id, change!.id));
    return saved!;
  });
}

export async function decideGovernanceChange(ctx: AccessContext, changeId: string, decision: "approve" | "reject") {
  const [found] = await systemDb().select({ tenantId: governanceChanges.tenantId }).from(governanceChanges).where(eq(governanceChanges.id, changeId));
  if (!found) throw new AccessDenied("change");
  assertSteward(ctx, found.tenantId);
  const who = actor(ctx);
  return withScope(systemScope(found.tenantId), async (tx) => {
    const [change] = await tx.select().from(governanceChanges).where(eq(governanceChanges.id, changeId)).for("update");
    if (!change || change.status !== "pending") throw new GovernanceError("closed");
    if (decision === "reject") {
      await tx.update(governanceChanges).set({ status: "rejected", decidedBy: ctx.principal.userId, decidedAt: new Date() }).where(eq(governanceChanges.id, changeId));
      await audit(tx, { ...who, tenantId: change.tenantId, action: "governance.reject", targetType: "governance_change", targetId: changeId });
      await notifyStewards(tx, change.tenantId, { type: "governance_change", id: changeId }, "Data rules change rejected", `${ctx.principal.name} rejected: ${diffProfile(change.before, change.after).join("; ")}.`);
      return { status: "rejected" as const };
    }
    if (change.proposedBy === ctx.principal.userId) throw new GovernanceError("self");
    if (change.approvals.includes(ctx.principal.userId)) throw new GovernanceError("twice");
    const approvals = [...change.approvals, ctx.principal.userId];
    await audit(tx, { ...who, tenantId: change.tenantId, action: "governance.approve", targetType: "governance_change", targetId: changeId, detail: { approvals: approvals.length, required: change.required } });
    if (approvals.length < change.required) {
      await tx.update(governanceChanges).set({ approvals }).where(eq(governanceChanges.id, changeId));
      return { status: "pending" as const };
    }
    await apply(tx, change, approvals, who);
    return { status: "applied" as const };
  });
}

/** Onboarding writes the most protective profile. It needs no steward: nothing is loosened. */
export async function initialiseGovernance(tx: Tx, tenantId: string, who: { actorId: string | null; actorKind: "user" | "system" }) {
  const [existing] = await tx.select({ tenantId: dataGovernance.tenantId }).from(dataGovernance).where(eq(dataGovernance.tenantId, tenantId));
  if (existing) return false;
  await tx.insert(dataGovernance).values({ tenantId, profile: MOST_PROTECTIVE });
  await audit(tx, { ...who, tenantId, action: "governance.initialise", targetType: "tenant", targetId: tenantId, detail: { profile: MOST_PROTECTIVE } });
  return true;
}
