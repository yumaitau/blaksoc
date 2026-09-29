import { and, desc, eq } from "drizzle-orm";
import type { Tx } from "@/db/client";
import { awarenessCampaigns, awarenessClicks } from "@/db/schema";
import { audit } from "@/lib/audit";
import type { AccessContext } from "@/lib/auth/access";
import { actor, inTenant } from "./common";

export class AwarenessError extends Error {
  constructor(readonly code: "consent" | "schedule" | "campaign" | "person") {
    super(code);
    this.name = "AwarenessError";
  }
}

export type ScheduleInput = {
  consented: boolean;
  scheduledAt: Date;
};

/** Customer admin consents and sets a time. This stores a record. It does not send mail. */
export async function scheduleCampaign(ctx: AccessContext, tenantId: string, input: ScheduleInput) {
  return inTenant(ctx, "user:manage", tenantId, async (tx) => {
    if (!input.consented) throw new AwarenessError("consent");
    if (!(input.scheduledAt instanceof Date) || Number.isNaN(input.scheduledAt.getTime())) throw new AwarenessError("schedule");
    const [row] = await tx.insert(awarenessCampaigns).values({
      tenantId,
      consented: true,
      scheduledAt: input.scheduledAt,
    }).returning({ id: awarenessCampaigns.id, scheduledAt: awarenessCampaigns.scheduledAt });
    if (!row) throw new AwarenessError("schedule");
    await audit(tx, { ...actor(ctx), tenantId, action: "awareness.schedule", targetType: "awareness_campaign", targetId: row.id, detail: { scheduledAt: row.scheduledAt.toISOString() } });
    return row;
  });
}

export async function latestCampaign(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "user:manage", tenantId, async (tx) => {
    const [row] = await tx.select().from(awarenessCampaigns).where(eq(awarenessCampaigns.tenantId, tenantId)).orderBy(desc(awarenessCampaigns.scheduledAt)).limit(1);
    return row ?? null;
  });
}

/** Fixture result for a practice campaign. No vendor is called. */
export async function recordPracticeClick(ctx: AccessContext, tenantId: string, campaignId: string, personLabel: string, when = new Date()) {
  const person = personLabel.trim().slice(0, 80);
  if (!person) throw new AwarenessError("person");
  return inTenant(ctx, "user:manage", tenantId, async (tx) => {
    const [campaign] = await tx.select({ id: awarenessCampaigns.id }).from(awarenessCampaigns).where(and(eq(awarenessCampaigns.id, campaignId), eq(awarenessCampaigns.tenantId, tenantId)));
    if (!campaign) throw new AwarenessError("campaign");
    const [row] = await tx.insert(awarenessClicks).values({
      tenantId,
      campaignId,
      personLabel: person,
      clickedAt: when,
    }).returning({ id: awarenessClicks.id });
    if (!row) throw new AwarenessError("campaign");
    return { id: row.id, person };
  });
}

/** People who clicked twice or more. For the customer admin, not the board. */
export async function listCoaching(ctx: AccessContext, tenantId: string) {
  return inTenant(ctx, "user:manage", tenantId, (tx) => coachingRows(tx, tenantId));
}

async function coachingRows(tx: Tx, tenantId: string) {
  const rows = await tx.select({ person: awarenessClicks.personLabel }).from(awarenessClicks).where(eq(awarenessClicks.tenantId, tenantId));
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(row.person, (counts.get(row.person) ?? 0) + 1);
  return [...counts.entries()].filter(([, n]) => n >= 2).map(([person, clicks]) => ({ person, clicks }));
}
